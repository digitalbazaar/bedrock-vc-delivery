/*!
 * Copyright (c) 2018-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from './exchanges.js';
import {createChallenge as _createChallenge, verify} from './verify.js';
import {
  buildPresentationFromResults, emitExchangeUpdated,
  evaluateTemplate, generateRandom,
  unenvelopePresentation, validateStep
} from './helpers.js';
import {exportJWK, generateKeyPair, importJWK} from 'jose';
import {compile} from '@bedrock/validation';
import {issue} from './issue.js';
import {logger} from './logger.js';

const {util: {BedrockError}} = bedrock;

const MAXIMUM_STEPS = 100;
const FIFTEEN_MINUTES = 60 * 15;

export async function createExchange({workflow, exchange}) {
  const {
    ttl = FIFTEEN_MINUTES, openId, variables = {},
    // allow steps to be skipped by creator as needed
    step = workflow.initialStep
  } = exchange;

  // validate exchange step, if given
  if(step && !(step in workflow.steps)) {
    throw new BedrockError(`Undefined step "${step}".`, {
      name: 'DataError',
      details: {httpStatusCode: 400, public: true}
    });
  }

  if(openId) {
    // either issuer instances or a single issuer zcap be given if
    // any expected credential requests are given
    const {expectedCredentialRequests} = openId;
    if(expectedCredentialRequests &&
      !(workflow.issuerInstances || workflow.zcaps.issue)) {
      throw new BedrockError(
        'Credential requests are not supported by this workflow.', {
          name: 'DataError',
          details: {httpStatusCode: 400, public: true}
        });
    }

    // perform key generation if requested
    if(openId.oauth2?.generateKeyPair) {
      const {oauth2} = openId;
      const {algorithm} = oauth2.generateKeyPair;
      const kp = await generateKeyPair(algorithm, {extractable: true});
      const [privateKeyJwk, publicKeyJwk] = await Promise.all([
        exportJWK(kp.privateKey),
        exportJWK(kp.publicKey),
      ]);
      oauth2.keyPair = {privateKeyJwk, publicKeyJwk};
      delete oauth2.generateKeyPair;
    } else {
      // ensure key pair can be imported
      try {
        const {oauth2: {keyPair}} = openId;
        await Promise.all([
          importJWK(keyPair.privateKeyJwk),
          importJWK(keyPair.publicKeyJwk)
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
  }

  // insert exchange
  const {id: workflowId} = workflow;
  exchange = {
    id: await generateRandom(),
    ttl,
    variables,
    openId,
    step
  };
  await exchanges.insert({workflowId, exchange});
  // FIXME: run parallel process to pre-warm cache with new exchange record
  return exchange;
}

export async function processExchange({req, res, workflow, exchangeRecord}) {
  const {exchange, meta} = exchangeRecord;
  let {updated: lastUpdated} = meta;
  try {
    // get any `verifiablePresentation` from the body...
    let receivedPresentation = req?.body?.verifiablePresentation;

    // process exchange step(s)
    let i = 0;
    let currentStep = exchange.step;
    let step;
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
      step = workflow.steps[currentStep];
      if(step.stepTemplate) {
        // generate step from the template; assume the template type is
        // `jsonata` per the JSON schema
        step = await evaluateTemplate(
          {workflow, exchange, typedTemplate: step.stepTemplate});
      }
      await validateStep({step});

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
        if(presentationSchema) {
          // if the VP is enveloped, get the presentation from the envelope
          let presentation;
          if(receivedPresentation?.type === 'EnvelopedVerifiablePresentation') {
            ({presentation} = await unenvelopePresentation({
              envelopedPresentation: receivedPresentation
            }));
          } else {
            presentation = receivedPresentation;
          }

          // validate the received VP
          const {jsonSchema: schema} = presentationSchema;
          const validate = compile({schema});
          const {valid, error} = validate(presentation);
          if(!valid) {
            throw error;
          }
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
        if(step.issueRequests?.length > 0) {
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
          lastUpdated = Date.now();
        } catch(e) {
          exchange.sequence--;
          throw e;
        } finally {
          emitExchangeUpdated({workflow, exchange, step});
        }

        // FIXME: there may be VCs to issue during this step, do so before
        // sending the VPR above
      } else if(step.nextStep) {
        // next steps without VPRs are prohibited
        throw new BedrockError(
          'Invalid step detected; continuing exchanges must include VPRs.', {
            name: 'DataError',
            details: {httpStatusCode: 500, public: true}
          });
      }
      currentStep = step.nextStep;
    }

    // mark exchange complete
    exchange.state = 'complete';
    try {
      exchange.sequence++;
      await exchanges.complete({workflowId: workflow.id, exchange});
    } catch(e) {
      exchange.sequence--;
      throw e;
    } finally {
      emitExchangeUpdated({workflow, exchange, step});
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
    exchanges.setLastError({workflowId, exchange: copy, lastUpdated})
      .catch(error => logger.error(
        'Could not set last exchange error: ' + error.message, {error}));
    throw e;
  }
}
