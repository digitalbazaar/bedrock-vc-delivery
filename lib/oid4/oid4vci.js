/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from '../exchanges.js';
import {
  evaluateTemplate, getWorkflowIssuerInstances
} from '../helpers.js';
import {importJWK, SignJWT} from 'jose';
import {checkAccessToken} from '@bedrock/oauth2-verifier';
import {getAuthorizationRequest} from './oid4vp.js';
import {issue} from '../issue.js';
import {timingSafeEqual} from 'node:crypto';
import {verifyDidProofJwt} from '../verify.js';

const {util: {BedrockError}} = bedrock;

const PRE_AUTH_GRANT_TYPE =
  'urn:ietf:params:oauth:grant-type:pre-authorized_code';

export function getAuthorizationServerConfig({exchangeId}) {
  // note that technically, we should not need to serve any credential
  // issuer metadata, but we do for backwards compatibility purposes as
  // previous versions of OID4VCI required it
  return getCredentialIssuerConfig({exchangeId});
}

export function getCredentialIssuerConfig({exchangeId}) {
  return {
    issuer: exchangeId,
    jwks_uri: `${exchangeId}/openid/jwks`,
    token_endpoint: `${exchangeId}/openid/token`,
    credential_endpoint: `${exchangeId}/openid/credential`,
    batch_credential_endpoint: `${exchangeId}/openid/batch_credential`,
    'pre-authorized_grant_anonymous_access_supported': true
  };
}

export async function getJwks({req}) {
  const {exchange} = await req.getExchange();
  if(!exchange.openId) {
    _throwUnsupportedProtocol();
  }
  return [exchange.openId.oauth2.keyPair.publicKeyJwk];
}

export async function processAccessTokenRequest({req}) {
  const exchangeRecord = await req.getExchange();
  const {exchange} = exchangeRecord;
  if(!exchange.openId) {
    _throwUnsupportedProtocol();
  }

  /* Examples of types of token requests:
  pre-authz code:
  grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
  &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
  &user_pin=493536

  authz code:
  grant_type=authorization_code
  &code=SplxlOBeZQQYbYS6WxSbIA
  &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  &redirect_uri=https%3A%2F%2FWallet.example.org%2Fcb */

  const {config: workflow} = req.serviceObject;

  const {
    grant_type: grantType,
    'pre-authorized_code': preAuthorizedCode,
    // FIXME: `user_pin` now called `tx_code`
    //user_pin: userPin
  } = req.body;

  if(grantType !== PRE_AUTH_GRANT_TYPE) {
    // unsupported grant type
    // FIXME: throw proper oauth2 formatted error
    throw new Error('Unsupported grant type.');
  }

  // validate grant type
  const {openId: {preAuthorizedCode: expectedCode}} = exchange;
  if(expectedCode) {
    // ensure expected pre-authz code matches
    if(!timingSafeEqual(
      Buffer.from(expectedCode, 'utf8'),
      Buffer.from(preAuthorizedCode, 'utf8'))) {
      // FIXME: throw proper oauth2 formatted error
      throw new Error('invalid pre-authorized-code or user pin');
    }
  }

  // create access token
  const {accessToken, ttl} = await _createExchangeAccessToken({
    workflow, exchangeRecord
  });
  return {
    access_token: accessToken,
    token_type: 'bearer',
    expires_in: ttl
  };
}

export async function processCredentialRequests({req, res, isBatchRequest}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  const {exchange} = exchangeRecord;
  if(!exchange.openId) {
    _throwUnsupportedProtocol();
  }

  // ensure oauth2 access token is valid
  await _checkAuthz({req, workflow, exchange});

  // validate body against expected credential requests
  const {openId: {expectedCredentialRequests}} = exchange;
  let credentialRequests;
  if(isBatchRequest) {
    ({credential_requests: credentialRequests} = req.body);
  } else {
    if(expectedCredentialRequests.length > 1) {
      // clients interacting with exchanges with more than one VC to be
      // delivered must use the "batch credential" endpoint
      // FIXME: improve error
      throw new Error('batch_credential_endpoint must be used');
    }
    credentialRequests = [req.body];
  }

  // before asserting, normalize credential requests to use `type` instead of
  // `types`; this is to allow for OID4VCI draft implementers that followed
  // the non-normative examples
  _normalizeCredentialDefinitionTypes({credentialRequests});
  const {format} = _assertCredentialRequests({
    workflow, credentialRequests, expectedCredentialRequests
  });

  // process exchange step if present
  const currentStep = exchange.step;
  if(currentStep) {
    let step = workflow.steps[exchange.step];
    if(step.stepTemplate) {
      // generate step from the template; assume the template type is
      // `jsonata` per the JSON schema
      step = await evaluateTemplate(
        {workflow, exchange, typedTemplate: step.stepTemplate});
      if(Object.keys(step).length === 0) {
        throw new BedrockError('Could not create exchange step.', {
          name: 'DataError',
          details: {httpStatusCode: 500, public: true}
        });
      }
    }

    // do late workflow configuration validation
    const {jwtDidProofRequest, openId} = step;
    // use of `jwtDidProofRequest` and `openId` together is prohibited
    if(jwtDidProofRequest && openId) {
      throw new BedrockError(
        'Invalid workflow configuration; only one of ' +
        '"jwtDidProofRequest" and "openId" is permitted in a step.', {
          name: 'DataError',
          details: {httpStatusCode: 500, public: true}
        });
    }

    // check to see if step supports OID4VP
    if(step.openId) {
      // if there is no `presentationSubmission`, request one
      const {results} = exchange.variables;
      if(!results?.[exchange.step]?.openId?.presentationSubmission) {
        // FIXME: optimize away double step-template processing that currently
        // occurs when calling `_getAuthorizationRequest`
        const {
          authorizationRequest
        } = await getAuthorizationRequest({req});
        return _requestOID4VP({authorizationRequest, res});
      }
      // otherwise drop down below to complete exchange...
    } else if(jwtDidProofRequest) {
      // handle OID4VCI specialized JWT DID Proof request...

      // `proof` must be in every credential request; if any requets is missing
      // `proof` then request a DID proof
      if(credentialRequests.some(cr => !cr.proof?.jwt)) {
        return _requestDidProof({res, exchangeRecord});
      }

      // verify every DID proof and get resulting DIDs
      const results = await Promise.all(
        credentialRequests.map(async cr => {
          const {proof: {jwt}} = cr;
          const {did} = await verifyDidProofJwt({workflow, exchange, jwt});
          return did;
        }));
      // require `did` to be the same for every proof
      // FIXME: determine if this needs to be more flexible
      const did = results[0];
      if(results.some(d => did !== d)) {
        // FIXME: improve error
        throw new Error('every DID must be the same');
      }
      // store did results in variables associated with current step
      if(!exchange.variables.results) {
        exchange.variables.results = {};
      }
      exchange.variables.results[currentStep] = {
        // common use case of DID Authentication; provide `did` for ease
        // of use in templates
        did
      };
    }
  }

  // mark exchange complete
  exchange.sequence++;
  await exchanges.complete({workflowId: workflow.id, exchange});

  // FIXME: decide what the best recovery path is if delivery fails (but no
  // replay attack detected) after exchange has been marked complete

  // issue VCs
  return issue({workflow, exchange, format});
}

function _assertCredentialRequests({
  workflow, credentialRequests, expectedCredentialRequests
}) {
  // ensure that every credential request is for the same format
  /* credential requests look like:
  {
    format: 'ldp_vc',
    credential_definition: { '@context': [Array], type: [Array] }
  }
  */
  let sharedFormat;
  if(!credentialRequests.every(({format}) => {
    if(sharedFormat === undefined) {
      sharedFormat = format;
    }
    return sharedFormat === format;
  })) {
    throw new BedrockError(
      'Credential requests must all use the same format in this workflow.', {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true}
      });
  }

  // get all supported formats from available issuer instances; for simple
  // workflow configs, a single issuer instance is used with only
  // ensure that every credential request uses a format supported by
  // issuer instances
  const supportedFormats = new Set();
  const issuerInstances = getWorkflowIssuerInstances({workflow});
  issuerInstances.forEach(
    instance => instance.supportedFormats.forEach(
      supportedFormats.add, supportedFormats));
  if(!supportedFormats.has(sharedFormat)) {
    throw new BedrockError(
      `Credential request format "${sharedFormat}" is not supported ` +
      'by this workflow.', {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true}
      });
  }

  // ensure every credential request matches against an expected one and none
  // are missing; `expectedCredentialRequests` formats are ignored based on the
  // issuer instance supported formats and have already been checked
  if(!(credentialRequests.length === expectedCredentialRequests.length &&
    credentialRequests.every(cr => expectedCredentialRequests.some(
      expected => _matchCredentialRequest(expected, cr))))) {
    throw new BedrockError(
      'Unexpected credential request.', {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true}
      });
  }

  return {format: sharedFormat};
}

async function _createExchangeAccessToken({workflow, exchangeRecord}) {
  // FIXME: set `exp` to max of 15 minutes / configured max minutes
  const expires = exchangeRecord.meta.expires;
  const exp = Math.floor(expires.getTime() / 1000);

  // create access token
  const {exchange} = exchangeRecord;
  const {openId: {oauth2: {keyPair: {privateKeyJwk}}}} = exchange;
  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  const {accessToken, ttl} = await _createOAuth2AccessToken({
    privateKeyJwk, audience: exchangeId, action: 'write', target: exchangeId,
    exp, iss: exchangeId
  });
  return {accessToken, ttl};
}

async function _createOAuth2AccessToken({
  privateKeyJwk, audience, action, target, exp, iss, nbf, typ = 'at+jwt'
}) {
  const alg = _getAlgFromPrivateKey({privateKeyJwk});
  const scope = `${action}:${target}`;
  const builder = new SignJWT({scope})
    .setProtectedHeader({alg, typ})
    .setIssuer(iss)
    .setAudience(audience);
  let ttl;
  if(exp !== undefined) {
    builder.setExpirationTime(exp);
    ttl = Math.max(0, exp - Math.floor(Date.now() / 1000));
  } else {
    // default to 15 minute expiration time
    builder.setExpirationTime('15m');
    ttl = Math.floor(Date.now() / 1000) + 15 * 60;
  }
  if(nbf !== undefined) {
    builder.setNotBefore(nbf);
  }
  const key = await importJWK({...privateKeyJwk, alg});
  const accessToken = await builder.sign(key);
  return {accessToken, ttl};
}

async function _checkAuthz({req, workflow, exchange}) {
  // optional oauth2 options
  const {oauth2} = exchange.openId;
  const {maxClockSkew} = oauth2;

  // audience is always the `exchangeId` and cannot be configured; this
  // prevents attacks where access tokens could otherwise be generated
  // if the AS keys were compromised; the `exchangeId` must also be known
  const exchangeId = `${workflow.id}/exchanges/${req.params.exchangeId}`;
  const audience = exchangeId;

  // `issuerConfigUrl` is always based off of the `exchangeId` as well
  const parsedIssuer = new URL(exchangeId);
  const issuerConfigUrl =
    `${parsedIssuer.origin}/.well-known/oauth-authorization-server` +
    parsedIssuer.pathname;

  // FIXME: `allowedAlgorithms` should be computed from `oauth2.keyPair`
  // const allowedAlgorithms =

  // ensure access token is valid
  await checkAccessToken({req, issuerConfigUrl, maxClockSkew, audience});
}

function _getAlgFromPrivateKey({privateKeyJwk}) {
  if(privateKeyJwk.alg) {
    return privateKeyJwk.alg;
  }
  if(privateKeyJwk.kty === 'EC' && privateKeyJwk.crv) {
    if(privateKeyJwk.crv.startsWith('P-')) {
      return `ES${privateKeyJwk.crv.slice(2)}`;
    }
    if(privateKeyJwk.crv === 'secp256k1') {
      return 'ES256K';
    }
  }
  if(privateKeyJwk.kty === 'OKP' && privateKeyJwk.crv?.startsWith('Ed')) {
    return 'EdDSA';
  }
  if(privateKeyJwk.kty === 'RSA') {
    return 'PS256';
  }
  return 'invalid';
}

function _matchCredentialRequest(expected, cr) {
  const {credential_definition: {'@context': c1, type: t1}} = expected;
  const {credential_definition: {'@context': c2, type: t2}} = cr;
  // contexts must match exact order but types can have different order
  return (c1.length === c2.length && t1.length === t2.length &&
    c1.every((c, i) => c === c2[i]) && t1.every(t => t2.some(x => t === x)));
}

function _normalizeCredentialDefinitionTypes({credentialRequests}) {
  // normalize credential requests to use `type` instead of `types`
  for(const cr of credentialRequests) {
    if(cr?.credential_definition?.types) {
      if(!cr?.credential_definition?.type) {
        cr.credential_definition.type = cr.credential_definition.types;
      }
      delete cr.credential_definition.types;
    }
  }
}

async function _requestDidProof({res, exchangeRecord}) {
  /* `9.4 Credential Issuer-provided nonce` allows the credential
  issuer infrastructure to provide the nonce via an error:

  HTTP/1.1 400 Bad Request
  Content-Type: application/json
  Cache-Control: no-store

  {
    "error": "invalid_or_missing_proof"
    "error_description":
        "Credential issuer requires proof element in Credential Request"
    "c_nonce": "8YE9hCnyV2",
    "c_nonce_expires_in": 86400
  }*/

  /* OID4VCI exchanges themselves are not replayable and single-step, so the
  challenge to be signed is just the exchange ID itself. An exchange cannot
  be reused and neither can a challenge. */
  const {exchange, meta: {expires}} = exchangeRecord;
  const ttl = Math.floor((expires.getTime() - Date.now()) / 1000);

  res.status(400).json({
    error: 'invalid_or_missing_proof',
    error_description:
      'Credential issuer requires proof element in Credential Request',
    // use exchange ID
    c_nonce: exchange.id,
    // use exchange expiration period
    c_nonce_expires_in: ttl
  });
}

async function _requestOID4VP({authorizationRequest, res}) {
  /* Error thrown when OID4VP is required to complete OID4VCI:

  HTTP/1.1 400 Bad Request
  Content-Type: application/json
  Cache-Control: no-store

  {
    "error": "presentation_required"
    "error_description":
      "Credential issuer requires presentation before Credential Request"
    "authorization_request": {
      "response_type": "vp_token",
      "presentation_definition": {
        id: "<urn:uuid>",
        input_descriptors: {...}
      },
      "response_mode": "direct_post"
    }
  }*/

  /* OID4VCI exchanges themselves are not replayable and single-step, so the
  challenge to be signed is just the exchange ID itself. An exchange cannot
  be reused and neither can a challenge. */

  res.status(400).json({
    error: 'presentation_required',
    error_description:
      'Credential issuer requires presentation before Credential Request',
    authorization_request: authorizationRequest
  });
}

function _throwUnsupportedProtocol() {
  // FIXME: improve error
  // unsupported protocol for the exchange
  throw new Error('Unsupported protocol.');
}
