/*!
 * Copyright (c) 2018-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from './storage/exchanges.js';
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

import {ExchangeProcessor} from './ExchangeProcessor.js';

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
  // get any `verifiablePresentation` from the body...
  const receivedPresentation = req?.body?.verifiablePresentation;

  // use exchange processor to generate a response
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    inputRequired({step}) {
      return step.verifiablePresentationRequest && !receivedPresentation;
    },
    validateStep({workflow, step}) {
      if(!_supportsVcApi({workflow, step})) {
        throw new BedrockError(
          'VC API protocol not supported by this exchange.', {
            name: 'NotSupportedError',
            details: {httpStatusCode: 400, public: true}
          });
      }
    }
  });
  const response = await exchangeProcessor.process({receivedPresentation});

  // send response
  res.json(response);
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
