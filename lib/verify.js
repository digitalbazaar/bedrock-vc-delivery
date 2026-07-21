/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  createVerifyOptions,
  getZcapClient,
  stripStacktrace
} from './helpers.js';
import {importJWK, jwtVerify} from 'jose';
import {compile} from '@bedrock/validation';
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
  workflow, verifyPresentationOptions, verifiablePresentationRequest,
  presentation, allowUnprotectedPresentation = false,
  expectedChallenge, expectedDomain,
  verifyPresentationResultSchema
} = {}) {
  // create zcap client for verifying
  const {zcapClient, zcaps} = await getZcapClient({workflow});

  // determine if presentation is secured or not
  const isSecured = presentation?.proof ||
    presentation?.type === 'EnvelopedVerifiablePresentation';

  const checks = (!isSecured && allowUnprotectedPresentation) ? [] : ['proof'];
  if(!expectedChallenge) {
    // if no expected challenge, rely on verifier for challenge management
    checks.push('challenge');
  }

  // verify presentation
  let result;
  try {
    const domain = expectedDomain ??
      verifiablePresentationRequest?.domain ?? new URL(workflow.id).origin;
    const options = createVerifyOptions({
      verifyPresentationOptions,
      expectedChallenge,
      verifiablePresentationRequest,
      presentation,
      domain,
      checks
    });
    const capability = zcaps.verifyPresentation;
    result = await zcapClient.write({
      capability,
      json: {
        options,
        verifiablePresentation: presentation
      }
    });
  } catch(cause) {
    if(!cause.data?.error) {
      throw new BedrockError(cause.data?.message || cause.message, {
        name: 'OperationError',
        cause,
        details: {
          httpStatusCode: cause.status ?? 500,
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
    if(presentationResult?.error) {
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
        httpStatusCode: cause.status ?? 500,
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
  const verificationMethod = presentationResult?.results?.[0]
    ?.verificationMethod ?? null;

  // validate against the verify presentation result schema, if applicable
  if(verifyPresentationResultSchema) {
    const {jsonSchema: schema} = verifyPresentationResultSchema;
    const validate = compile({schema});
    const {valid, error} = validate(result.data);
    if(!valid) {
      throw error;
    }
  }

  return {
    verified,
    challengeUses,
    verificationMethod: await _toMultikey({
      vm: verificationMethod
    }),
    publicKeyJwk: await _toJwk(verificationMethod),
    credentialResults,
    presentationResult
  };
}

export async function verifyCredentialRequestProof({
  credentialRequest, workflow, exchange
} = {}) {
  // FIXME: do not support more than one proof of each type at this time
  const jwt = credentialRequest.proofs.jwt?.[0];
  const diVp = credentialRequest.proofs.di_vp?.[0];

  let _did;
  const dids = [];
  const verifyResults = {};
  if(diVp) {
    const result = await verifyDidProofDiVp({workflow, exchange, diVp});
    verifyResults.di_vp = verifyResults.di_vp ?? [];
    // return results w/both common key formats
    verifyResults.di_vp.push({
      did: result.did,
      verificationMethod: await _toMultikey({
        vm: result.verifyResult.verificationMethod
      }),
      publicKeyJwk: await _toJwk(result.verifyResult.verificationMethod)
    });
    dids.push(result.did);
    _did = result.did;
  }
  if(jwt) {
    const result = await verifyDidProofJwt({workflow, exchange, jwt});
    verifyResults.jwt = verifyResults.jwt ?? [];
    // return results w/both common key formats
    verifyResults.jwt.push({
      did: result.did,
      verificationMethod: await _toMultikey({
        jwk: result.verifyResult.jwk, controller: result.did
      }),
      publicKeyJwk: result.verifyResult.jwk
    });
    dids.push(result.did);
    if(_did === undefined) {
      _did = result.did;
    }
  }

  if(dids.some(d => d !== _did)) {
    // FIXME: improve error
    throw new Error('every DID must be the same');
  }

  return {did: _did, credentialRequest, verifyResults};
}

export async function verifyDidProofDiVp({workflow, exchange, diVp} = {}) {
  // domain is always the `exchangeId` and cannot be configured; this
  // prevents attacks where access tokens could otherwise be generated
  // if the AS keys were compromised; the `exchangeId` must also be known
  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  const verifyResult = await verify({
    workflow,
    presentation: diVp,
    // challenge is always local exchange ID; which is what is returned from
    // nonce endpoint; VCALM exchanges are short-lived and are capability URLs
    expectedChallenge: exchange.id,
    expectedDomain: exchangeId
  });
  // FIXME: ensure cryptosuite used matches a supported `di_vp` proof type
  const did = verifyResult.verificationMethod.controller;
  return {verified: true, did, verifyResult};
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
  let jwk;
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
    if(!(match && (Array.isArray(match.controller) ?
      match.controller.includes(vm.controller) :
      match.controller === vm.controller))) {
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
  // FIXME: ensure algorithm used matches a supported `jwt` algs
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
    verifyResult = {payload, protectedHeader, jwk};
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

function _getJwkAlgFromMultibase(mb) {
  if(mb.startsWith('zDna')) {
    return 'ES256';
  }
  if(mb.startsWith('z82L')) {
    return 'ES384';
  }
  if(mb.startsWith('z6Mk')) {
    return 'EdDSA';
  }
}

async function _toJwk(vm) {
  if(!vm) {
    return;
  }
  let jwk;
  const alg = _getJwkAlgFromMultibase(vm.publicKeyMultibase);
  if(alg === 'EdDSA') {
    const keyPair = await Ed25519Multikey.from(vm);
    jwk = await Ed25519Multikey.toJwk({keyPair});
    jwk.alg = 'EdDSA';
  } else if(alg?.startsWith('ES')) {
    const keyPair = await EcdsaMultikey.from(vm);
    jwk = await EcdsaMultikey.toJwk({keyPair});
    jwk.alg = alg;
  }
  return jwk;
}

async function _toMultikey({vm, jwk, controller}) {
  let keyPair;
  if(jwk) {
    if(jwk.alg === 'EdDSA') {
      keyPair = await Ed25519Multikey.fromJwk({jwk, controller});
    }
    if(jwk.alg.startsWith('ES')) {
      keyPair = await EcdsaMultikey.fromJwk({jwk, controller});
    }
  } else if(vm) {
    if(vm.type === 'Multikey') {
      return vm;
    }
    const alg = _getJwkAlgFromMultibase(vm.publicKeyMultibase);
    if(alg === 'EdDSA') {
      keyPair = await Ed25519Multikey.from(vm);
    } else if(alg.startsWith('ES')) {
      keyPair = await EcdsaMultikey.from(vm);
    }
  }

  if(keyPair) {
    return keyPair.export();
  }
}
