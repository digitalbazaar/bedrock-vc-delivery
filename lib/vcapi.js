/*!
 * Copyright (c) 2018-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from './exchanges.js';
import {createChallenge as _createChallenge, verify} from './verify.js';
import {
  buildPresentationFromResults,
  buildVerifyPresentationResults,
  emitExchangeUpdated,
  evaluateExchangeStep,
  generateRandom, validateVerifiablePresentation
} from './helpers.js';
import {exportJWK, generateKeyPair, importJWK} from 'jose';
import {issue} from './issue.js';
import {logger} from './logger.js';

// supported protocols
import * as inviteRequest from './inviteRequest/inviteRequest.js';
import * as oid4vci from './oid4/oid4vci.js';
import * as oid4vp from './oid4/oid4vp.js';

const {util: {BedrockError}} = bedrock;

const MAXIMUM_STEPS = 100;
const FIFTEEN_MINUTES = 60 * 15;

// 48 hours; make configurable
const MAX_TTL_IN_MS = 1000 * 60 * 60 * 24 * 2;

export async function createExchange({workflow, exchange}) {
  const {
    expires,
    ttl = FIFTEEN_MINUTES,
    variables = {},
    // allow steps to be skipped by creator as needed
    step: stepName = workflow.initialStep,
    openId
  } = exchange;

  // validate exchange step, if given
  if(stepName && !(stepName in workflow.steps)) {
    throw new BedrockError(`Undefined step "${stepName}".`, {
      name: 'DataError',
      details: {httpStatusCode: 400, public: true}
    });
  }

  // prepare new exchange object
  exchange = {
    id: await generateRandom(),
    expires,
    variables,
    step: stepName
  };
  if(openId) {
    exchange.openId = {...openId, oauth2: await _initOAuth2(openId)};
  }
  if(expires === undefined) {
    // `ttl` is used and is in seconds, convert to `expires`
    const date = new Date(Date.now() + ttl * 1000);
    exchange.expires = date.toISOString().replace(/\.\d+Z$/, 'Z');
  }

  // should expires isn't too far into the future
  const maxExpires = new Date(Date.now() + MAX_TTL_IN_MS);
  if(new Date(exchange.expires) > maxExpires) {
    throw new BedrockError(
      'Maximum exchange expiration date is "' +
      `${maxExpires.toISOString().replace(/\.\d+Z$/, 'Z')}".`, {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true}
      });
  }

  // if present, early-evaluate first step
  let initialStep;
  if(stepName) {
    initialStep = await evaluateExchangeStep({workflow, exchange, stepName});
  }

  // run protocol-specific initialization code
  await inviteRequest.initExchange({workflow, exchange, initialStep});
  await oid4vci.initExchange({workflow, exchange, initialStep});
  await oid4vp.initExchange({workflow, exchange, initialStep});

  // initialize exchange protocols
  exchange.protocols = await _createProtocols({
    workflow, exchange, step: initialStep
  });

  // insert exchange
  const {id: workflowId} = workflow;
  await exchanges.insert({workflowId, exchange});
  // FIXME: run parallel process to pre-warm cache with new exchange record
  return exchange;
}

export async function getProtocols({req} = {}) {
  // if `exchange.protocols` is set, use it
  const {config: workflow} = req.serviceObject;
  const {exchange} = await req.getExchange();
  if(exchange.protocols) {
    return exchange.protocols;
  }

  // dynamically construct and return `protocols` object...
  const step = await evaluateExchangeStep({
    workflow, exchange, stepName: workflow.initialStep
  });
  return _createProtocols({workflow, exchange, step});
}

export async function processExchange({req, res, workflow, exchangeRecord}) {
  const {exchange, meta} = exchangeRecord;
  let {updated: lastUpdated} = meta;
  let step;

  try {
    // get any `verifiablePresentation` from the body...
    let receivedPresentation = req?.body?.verifiablePresentation;

    // process exchange step(s)
    let i = 0;
    let currentStep = exchange.step;
    while(true) {
      if(i++ > MAXIMUM_STEPS) {
        throw new BedrockError('Maximum steps exceeded.', {
          name: 'DataError',
          details: {httpStatusCode: 500, public: true}
        });
      }

      // no step present, break out to complete exchange
      if(!currentStep) {
        break;
      }

      // get current step details
      step = await evaluateExchangeStep({
        workflow, exchange, stepName: currentStep
      });

      // if step does not support VCAPI, throw
      if(!_supportsVcApi({workflow, step})) {
        throw new BedrockError(
          'VC API protocol not supported by this exchange.', {
            name: 'NotSupportedError',
            details: {httpStatusCode: 400, public: true}
          });
      }

      // if next step is the same as the current step, throw an error
      if(step.nextStep === currentStep) {
        throw new BedrockError('Cyclical step detected.', {
          name: 'DataError',
          details: {httpStatusCode: 500, public: true}
        });
      }

      // handle VPR: if step requires it, then `verifiablePresentation` must
      // be in the request
      if(step.verifiablePresentationRequest) {
        const {createChallenge} = step;
        const isInitialStep = exchange.step === workflow.initialStep;

        // if no presentation was received in the body...
        if(!receivedPresentation) {
          const verifiablePresentationRequest = structuredClone(
            step.verifiablePresentationRequest);
          if(createChallenge) {
            /* Note: When creating a challenge, the initial step always
            uses the local exchange ID because the initial step itself
            is one-time use. Subsequent steps, which only VC-API (as opposed
            to other protocols) supports creating additional challenges via
            the VC-API verifier API. */
            let challenge;
            if(isInitialStep) {
              challenge = exchange.id;
            } else {
              // generate a new challenge using verifier API
              ({challenge} = await _createChallenge({workflow}));
            }
            verifiablePresentationRequest.challenge = challenge;
          }
          // send VPR and return
          res.json({verifiablePresentationRequest});
          // if exchange is pending, mark it as active out-of-band
          if(exchange.state === 'pending') {
            exchange.state = 'active';
            exchange.sequence++;
            exchanges.update({workflowId: workflow.id, exchange}).catch(
              error => logger.error(
                'Could not mark exchange active: ' + error.message, {error}));
          }
          return;
        }

        const {presentationSchema} = step;

        const isEnvelopedVP =
          receivedPresentation?.type === 'EnvelopedVerifiablePresentation';

        if(presentationSchema && !isEnvelopedVP) {
          validateVerifiablePresentation({
            schema: presentationSchema.jsonSchema,
            presentation: receivedPresentation
          });
        }

        // verify the received VP
        const expectedChallenge = isInitialStep ? exchange.id : undefined;
        const {
          allowUnprotectedPresentation = false,
          verifyPresentationOptions = {},
          verifyPresentationResultSchema
        } = step;
        const verifyResult = await verify({
          workflow,
          verifyPresentationOptions,
          verifyPresentationResultSchema,
          verifiablePresentationRequest: step.verifiablePresentationRequest,
          presentation: receivedPresentation,
          allowUnprotectedPresentation,
          expectedChallenge
        });

        // validate enveloped VP after verification
        if(presentationSchema && isEnvelopedVP) {
          validateVerifiablePresentation({
            schema: presentationSchema.jsonSchema,
            presentation: verifyResult?.presentationResult?.presentation ?? {}
          });
        }

        // store VP results in variables associated with current step
        if(!exchange.variables.results) {
          exchange.variables.results = {};
        }
        const {verificationMethod} = verifyResult;
        const result = {
          // common use case of DID Authentication; provide `did` for ease
          // of use in templates and consistency with OID4VCI which only
          // receives `did` not verification method nor VP
          did: verificationMethod?.controller || null,
          verificationMethod,
          verifiablePresentation: buildPresentationFromResults({
            presentation: receivedPresentation,
            verifyResult
          }),
          verifyPresentationResults: buildVerifyPresentationResults({
            verifyResult
          })
        };
        exchange.variables.results[currentStep] = result;

        // clear received presentation as it has been processed
        receivedPresentation = null;

        // if there is no next step, break out to complete exchange
        if(!step.nextStep) {
          break;
        }

        // FIXME: remove this once the other FIXME below is implemented
        // and provides support for issuance in non-last step
        if(step.verifiablePresentation || step.issueRequests?.length > 0) {
          throw new BedrockError(
            'Invalid step detected; continuing exchanges currently must ' +
            'only issue in the final step.', {
              name: 'DataError',
              details: {httpStatusCode: 500, public: true}
            });
        }

        // update the exchange to go to the next step, then loop to send
        // next VPR
        exchange.step = step.nextStep;
        // ensure exchange state is active
        if(exchange.state === 'pending') {
          exchange.state = 'active';
        }
        try {
          exchange.sequence++;
          await exchanges.update({workflowId: workflow.id, exchange});
          await emitExchangeUpdated({workflow, exchange, step});
          lastUpdated = Date.now();
        } catch(e) {
          exchange.sequence--;
          throw e;
        }

        // FIXME: there may be VCs to issue during this step, do so before
        // sending the VPR above and remove error that prevents continuing
        // exchanges that issue
      }
      currentStep = step.nextStep;
    }

    // mark exchange complete
    exchange.state = 'complete';
    try {
      exchange.sequence++;
      await exchanges.complete({workflowId: workflow.id, exchange});
      await emitExchangeUpdated({workflow, exchange, step});
    } catch(e) {
      exchange.sequence--;
      throw e;
    }
    lastUpdated = Date.now();

    // FIXME: decide what the best recovery path is if delivery fails (but no
    // replay attack detected) after exchange has been marked complete

    // issue any VCs; may return an empty response if the step defines no
    // VCs to issue
    const {response} = await issue({workflow, exchange, step});

    // if last `step` has a redirect URL, include it in the response
    if(step?.redirectUrl) {
      response.redirectUrl = step.redirectUrl;
    }

    // send response
    res.json(response);
  } catch(e) {
    if(e.name === 'InvalidStateError') {
      throw e;
    }
    // write last error if exchange hasn't been frequently updated
    const {id: workflowId} = workflow;
    const copy = {...exchange};
    copy.sequence++;
    copy.lastError = e;
    await exchanges.setLastError({workflowId, exchange: copy, lastUpdated})
      .catch(error => logger.error(
        'Could not set last exchange error: ' + error.message, {error}));
    await emitExchangeUpdated({workflow, exchange, step});
    throw e;
  }
}

async function _initOAuth2({oauth2}) {
  oauth2 = {...oauth2};

  // perform oauth2 key generation if requested
  if(oauth2.generateKeyPair) {
    const {algorithm} = oauth2.generateKeyPair;
    const kp = await generateKeyPair(algorithm, {extractable: true});
    const [privateKeyJwk, publicKeyJwk] = await Promise.all([
      exportJWK(kp.privateKey),
      exportJWK(kp.publicKey)
    ]);
    oauth2.keyPair = {privateKeyJwk, publicKeyJwk};
    delete oauth2.generateKeyPair;
  } else {
    // ensure key pair can be imported
    try {
      const {keyPair} = oauth2;
      let alg;
      if(!keyPair.privateKeyJwk.alg) {
        if(keyPair.privateKeyJwk.crv === 'Ed25519') {
          alg = 'EdDSA';
        } else if(keyPair.privateKeyJwk.crv?.startsWith('P-')) {
          alg = `ES${keyPair.privateKeyJwk.crv.slice(2)}`;
        }
      }
      await Promise.all([
        importJWK(keyPair.privateKeyJwk, alg),
        importJWK(keyPair.publicKeyJwk, alg)
      ]);
    } catch(e) {
      throw new BedrockError(
        'Could not import OpenID OAuth2 key pair.', {
          name: 'DataError',
          details: {httpStatusCode: 400, public: true},
          cause: e
        });
    }
  }

  return oauth2;
}

async function _createProtocols({workflow, exchange, step}) {
  // dynamically construct and return `protocols` object...
  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;

  // VC API protocols...
  let vcApiProtocols;
  if(_supportsVcApi({workflow, step})) {
    vcApiProtocols = {vcapi: exchangeId};
  }

  // invite request protocols
  let inviteRequestProtocols;
  if(inviteRequest.supportsInviteRequest({step})) {
    inviteRequestProtocols = inviteRequest.getInviteRequestProtocols({
      workflow, exchange, step
    });
  }

  // OID4* protocols...
  let oid4vciProtocols;
  let oid4vpProtocols;
  if(oid4vci.supportsOID4VCI({exchange})) {
    oid4vciProtocols = oid4vci.getOID4VCIProtocols({
      workflow, exchange, step
    });
  } else {
    // only add OID4VP protocols if OID4VCI is not supported to cover
    // OID4VCI+OID4VP combo case
    oid4vpProtocols = await oid4vp.getOID4VPProtocols({
      workflow, exchange, step
    });
  }

  // return merged protocols
  return {
    ...inviteRequestProtocols,
    ...oid4vciProtocols,
    ...oid4vpProtocols,
    ...vcApiProtocols
  };
}

function _supportsVcApi({workflow, step}) {
  return step?.verifiablePresentationRequest ||
    step?.verifiablePresentation ||
    workflow?.credentialTemplates?.length > 0;
}
