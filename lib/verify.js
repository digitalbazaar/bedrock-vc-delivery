/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {importJWK, jwtVerify} from 'jose';
import {didIo} from '@bedrock/did-io';
import {getZcapClient} from './helpers.js';

const {util: {BedrockError}} = bedrock;

export async function createChallenge({workflow} = {}) {
  // create zcap client for creating challenges
  const {zcapClient, zcaps} = await getZcapClient({workflow});

  // create challenge
  const capability = zcaps.createChallenge;
  const {data: {challenge}} = await zcapClient.write({capability, json: {}});
  return {challenge};
}

export async function verify({
  workflow, verifiablePresentationRequest, presentation,
  allowUnprotectedPresentation = false, expectedChallenge
} = {}) {
  // create zcap client for verifying
  const {zcapClient, zcaps} = await getZcapClient({workflow});

  // verify presentation
  const hasProof = presentation?.proof ||
    presentation?.type === 'EnvelopedVerifiablePresentation';

  const checks = (!hasProof && allowUnprotectedPresentation) ?
    [] : ['proof'];
  if(!expectedChallenge) {
    // if no expected challenge, rely on verifier for challenge management
    checks.push('challenge');
  }
  const capability = zcaps.verifyPresentation;
  const domain = verifiablePresentationRequest.domain ??
    new URL(workflow.id).origin;
  let result;
  try {
    result = await zcapClient.write({
      capability,
      json: {
        options: {
          // FIXME: support multi-proof presentations?
          challenge: expectedChallenge ??
            verifiablePresentationRequest.challenge ??
            presentation?.proof?.challenge,
          domain,
          checks
        },
        verifiablePresentation: presentation
      }
    });
  } catch(cause) {
    if(!cause.data?.error) {
      throw new BedrockError(cause.data?.message || cause.message, {
        name: 'OperationError',
        cause,
        details: {
          httpStatusCode: cause.status,
          public: true
        }
      });
    }

    // sanitize error stack traces
    const {verified, credentialResults, presentationResult} = cause.data;
    if(credentialResults) {
      credentialResults.forEach(result => {
        if(result.error) {
          result.error = _stripStacktrace(result.error);
        }
      });
    }
    if(presentationResult.error) {
      presentationResult.error = _stripStacktrace(presentationResult.error);
    }

    // generate useful error to return to client
    const {name, errors, message} = cause.data.error;
    const error = new BedrockError(message ?? 'Verification error.', {
      name: name === 'VerificationError' ? 'DataError' : 'OperationError',
      details: {
        verified,
        credentialResults,
        presentationResult,
        httpStatusCode: cause.status,
        public: true
      }
    });
    if(Array.isArray(errors)) {
      error.details.errors = errors.map(_stripStacktrace);
    }
    throw error;
  }

  const {
    data: {
      verified,
      challengeUses,
      credentialResults,
      presentationResult
    }
  } = result;

  // `presentationResult` is `undefined` when `proof` check is not run
  const verificationMethod = presentationResult?.results[0]
    .verificationMethod ?? null;

  // FIXME: ensure VP satisfies VPR

  return {
    verified,
    challengeUses,
    verificationMethod,
    credentialResults,
    presentationResult
  };
}

export async function verifyDidProofJwt({workflow, exchange, jwt} = {}) {
  // optional oauth2 options
  const {oauth2} = exchange.openId;
  const {maxClockSkew} = oauth2;

  // audience is always the `exchangeId` and cannot be configured; this
  // prevents attacks where access tokens could otherwise be generated
  // if the AS keys were compromised; the `exchangeId` must also be known
  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  const audience = exchangeId;

  let issuer;
  const resolveKey = async protectedHeader => {
    const vm = await didIo.get({url: protectedHeader.kid});
    // `vm.controller` must be the issuer of the DID JWT; also ensure that
    // the specified controller authorized `vm` for the purpose of
    // authentication
    issuer = vm.controller;
    const didDoc = await didIo.get({url: issuer});
    if(!(didDoc?.authentication?.some(e => e === vm.id || e.id === vm.id))) {
      throw new BedrockError(
        `Verification method controller "${issuer}" did not authorize ` +
        `verification method "${vm.id}" for the purpose of "authentication".`,
        {name: 'NotAllowedError'});
    }
    // FIXME: support other key types
    const keyPair = await Ed25519Multikey.from(vm);
    const jwk = await Ed25519Multikey.toJwk({keyPair});
    jwk.alg = 'EdDSA';
    return importJWK(jwk);
  };

  // FIXME: indicate supported signatures
  // const allowedAlgorithms = [];

  // use `jose` lib (for now) to verify JWT and return `payload`;
  // pass optional supported algorithms as allow list ... note
  // that `jose` *always* prohibits the `none` algorithm
  let verifyResult;
  try {
    // `jwtVerify` checks claims: `aud`, `exp`, `nbf`
    const {payload, protectedHeader} = await jwtVerify(jwt, resolveKey, {
      //algorithms: allowedAlgorithms,
      audience,
      clockTolerance: maxClockSkew
    });
    verifyResult = {payload, protectedHeader};
  } catch(e) {
    const details = {
      httpStatusCode: 403,
      public: true,
      code: e.code,
      reason: e.message
    };
    if(e.claim) {
      details.claim = e.claim;
    }
    throw new BedrockError('DID proof JWT validation failed.', {
      name: 'NotAllowedError',
      details
    });
  }

  // check `iss` claim
  if(!(verifyResult?.payload?.iss === issuer)) {
    throw new BedrockError('DID proof JWT validation failed.', {
      name: 'NotAllowedError',
      details: {
        httpStatusCode: 403,
        public: true,
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        reason: 'unexpected "iss" claim value.',
        claim: 'iss'
      }
    });
  }

  // check `nonce` claim
  if(!(verifyResult?.payload?.nonce === exchange.id)) {
    throw new BedrockError('DID proof JWT validation failed.', {
      name: 'NotAllowedError',
      details: {
        httpStatusCode: 403,
        public: true,
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        reason: 'unexpected "nonce" claim value.',
        claim: 'nonce'
      }
    });
  }

  return {verified: true, did: issuer, verifyResult};
}

function _stripStacktrace(error) {
  error = {...error};
  delete error.stack;
  if(error.errors) {
    error.errors = error.errors.map(_stripStacktrace);
  }
  if(error.cause) {
    error.cause = _stripStacktrace(error.cause);
  }
  return error;
}
