/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {getZcapClient, stripStacktrace} from './helpers.js';
import {importJWK, jwtVerify} from 'jose';
import {didIo} from '@bedrock/did-io';

const {util: {BedrockError}} = bedrock;

// supported JWT algs
const ECDSA_ALGS = ['ES256', 'ES384'];
const EDDSA_ALGS = ['Ed25519', 'EdDSA'];

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
          result.error = stripStacktrace(result.error);
        }
      });
    }
    if(presentationResult.error) {
      presentationResult.error = stripStacktrace(presentationResult.error);
    }

    // generate useful error to return to client
    const {name, errors, message} = cause.data.error;
    const causeError = stripStacktrace({...cause.data.error});
    delete causeError.errors;
    const error = new BedrockError(message ?? 'Verification error.', {
      name: (name === 'VerificationError' || name === 'DataError') ?
        'DataError' : 'OperationError',
      details: {
        error: causeError,
        verified,
        credentialResults,
        presentationResult,
        httpStatusCode: cause.status,
        public: true
      }
    });
    if(Array.isArray(errors)) {
      error.details.errors = errors.map(stripStacktrace);
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
  // `resolveKey` is passed `protectedHeader`
  const resolveKey = async ({alg, kid}) => {
    const isEcdsa = ECDSA_ALGS.includes(alg);
    const isEddsa = !isEcdsa && EDDSA_ALGS.includes(alg);
    if(!(isEcdsa || isEddsa)) {
      throw new BedrockError(
        `Unsupported JWT "alg": "${alg}".`, {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }

    const vm = await didIo.get({url: kid});
    if(!vm) {
      throw new BedrockError(
        `Verification method identified by "kid" (${kid}) could not be ` +
        'retrieved.', {
          name: 'DataError',
          details: {
            public: true,
            httpStatusCode: 400
          }
        });
    }

    // `vm.controller` must be the issuer of the DID JWT; also ensure that
    // the specified controller authorized `vm` for the purpose of
    // authentication
    issuer = vm.controller;
    const didDoc = await didIo.get({url: issuer});
    let match = didDoc?.authentication?.find?.(
      e => e === vm.id || e.id === vm.id);
    if(typeof match === 'string') {
      match = didDoc?.verificationMethod?.find?.(e => e.id === vm.id);
    }
    if(!(match && Array.isArray(match.controller) ?
      match.controller.includes(vm.controller) :
      match.controller === vm.controller)) {
      throw new BedrockError(
        `Verification method controller "${issuer}" did not authorize ` +
        `verification method "${vm.id}" for the purpose of "authentication".`, {
          name: 'NotAllowedError',
          details: {
            public: true,
            httpStatusCode: 400
          }
        });
    }
    let jwk;
    if(isEcdsa) {
      const keyPair = await EcdsaMultikey.from(vm);
      jwk = await EcdsaMultikey.toJwk({keyPair});
      jwk.alg = alg;
    } else {
      const keyPair = await Ed25519Multikey.from(vm);
      jwk = await Ed25519Multikey.toJwk({keyPair});
      jwk.alg = 'EdDSA';
    }
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
  if(!(issuer && verifyResult?.payload?.iss === issuer)) {
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
  if(verifyResult?.payload?.nonce !== exchange.id) {
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
