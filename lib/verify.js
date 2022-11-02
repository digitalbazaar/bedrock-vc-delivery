/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {didIo} from '@bedrock/did-io';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {getZcapClient} from './helpers.js';
import {importJWK, jwtVerify} from 'jose';

const {util: {BedrockError}} = bedrock;

export async function createChallenge({exchanger} = {}) {
  // create zcap client for creating challenges
  const {zcapClient, zcaps} = await getZcapClient({exchanger});

  // create challenge
  const capability = zcaps.verify;
  const {data: {challenge}} = await zcapClient.write({
    url: `${capability.invocationTarget}/challenges`,
    capability,
    json: {}
  });
  return {challenge};
}

export async function verify({exchanger, presentation} = {}) {
  // create zcap client for verifying
  const {zcapClient, zcaps} = await getZcapClient({exchanger});

  // verify presentation
  const capability = zcaps.verify;
  const result = await zcapClient.write({
    url: `${capability.invocationTarget}/presentations/verify`,
    capability,
    json: {
      options: {
        challenge,
        checks: ['proof'],
      },
      verifiablePresentation: presentation
    }
  });

  const {data: {verified, challengeUses}} = result;
  return {verified, challengeUses};
}

export async function verifyDidProofJwt({exchanger, exchange, jwt} = {}) {
  // optional oauth2 options
  const {oauth2} = exchange.oidc4vci;
  const {maxClockSkew} = oauth2;

  // audience is always the `exchangeId` and cannot be configured; this
  // prevents attacks where access tokens could otherwise be generated
  // if the AS keys were compromised; the `exchangeId` must also be known
  const exchangeId = `${exchanger.id}/exchanges/${exchange.id}`;
  const audience = exchangeId;

  let issuer;
  const resolveKey = async (protectedHeader, token) => {
    const document = await didIo.get({url: protectedHeader.kid});
    issuer = document.controller;
    // FIXME: support other key types
    const publicKey = await Ed25519VerificationKey2020.from(document);
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
  console.log('DID proof JWT verifyResult', verifyResult);

  return {verified: true, did: issuer, verifyResult};
}
