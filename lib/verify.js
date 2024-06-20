/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {importJWK, jwtVerify} from 'jose';
import {didIo} from '@bedrock/did-io';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
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
  const result = await zcapClient.write({
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

  const {
    data: {
      verified,
      challengeUses,
      presentationResult
    }
  } = result;

  // `presentationResult` is `undefined` when `proof` check is not run
  const verificationMethod = presentationResult?.results[0]
    .verificationMethod ?? null;

  // FIXME: ensure VP satisfies VPR

  return {verified, challengeUses, verificationMethod};
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
    const publicKey = await Ed25519VerificationKey2020.from(vm);
    const jwk = publicKey.toJwk();
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
