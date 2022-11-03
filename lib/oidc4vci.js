/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {importJWK, SignJWT} from 'jose';
import {
  oidc4vciCredentialBody, oidc4vciTokenBody
} from '../schemas/bedrock-vc-exchanger.js';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import {checkAccessToken} from '@bedrock/oauth2-verifier';
import cors from 'cors';
import {issue} from './issue.js';
import {timingSafeEqual} from 'node:crypto';
import {createValidateMiddleware as validate} from '@bedrock/validation';
import {verifyDidProofJwt} from './verify.js';

/* NOTE: Parts of the OIDC4VCI design imply tight integration between the
authorization server and the credential issuance / delivery server. This
file provides the routes for both and treats them as integrated; supporting
the OIDC4VCI pre-authz code flow only as a result. However, we also try to
avoid tight-coupling where possible to enable the non-pre-authz code flow
that would use, somehow, a separate authorization server.

One tight coupling we try to avoid involves the option where the authorization
server generates the challenge nonce to be signed in a DID proof, but the
credential delivery server is the system responsible for checking and tracking
this challenge. The Credential Delivery server cannot know the challenge is
authentic without breaking some abstraction around how the Authorization
Server is implemented behind its API. Here we do not implement this option,
instead, if a challenge is required, the credential delivery server will send
an error with the challenge nonce if one was not provided in the payload to the
credential endpoint. This error follows the OIDC4VCI spec and avoids this
particular tight coupling.

Other tight couplings cannot be avoided at this time -- such as the fact that
the credential endpoint is specified in the authorization server's metadata;
this creates challenges for SaaS based solutions and for issuers that want to
use multiple different Issuance / Delivery server backends. We solve these
challenges by using the "pre-authorized code" flows and effectively
instantiating a new authorization server instance per VC exchange. */

const PRE_AUTH_GRANT_TYPE =
  'urn:ietf:params:oauth:grant-type:pre-authorized_code';

// creates OIDC4VCI Authorization Server + Credential Delivery Server
// endpoints for each individual exchange
export async function createRoutes({
  app, exchangeRoute, getConfigMiddleware, getExchange
} = {}) {
  const oidc4vciRoute = `${exchangeRoute}/oidc4vci`;
  const routes = {
    asMetadata: `/.well-known/oauth-authorization-server${exchangeRoute}`,
    credential: `${oidc4vciRoute}/credential`,
    token: `${oidc4vciRoute}/token`,
    jwks: `${oidc4vciRoute}/jwks`
  };

  // urlencoded body parser (extended=true for rich JSON-like representation)
  const urlencoded = bodyParser.urlencoded({extended: true});

  // an authorization server endpoint
  // serves `.well-known` oauth2 AS config for each exchange; each config is
  // based on the exchanger used to create the exchange
  app.get(
    routes.asMetadata,
    cors(),
    getConfigMiddleware,
    asyncHandler(async (req, res) => {
      // generate well-known oauth2 issuer config
      const {config: exchanger} = req.serviceObject;
      const exchangeId = `${exchanger.id}/exchanges/${req.params.exchangeId}`;
      const oauth2Config = {
        issuer: exchangeId,
        jwks_uri: `${exchangeId}/oidc4vci/jwks`,
        token_endpoint: `${exchangeId}/oidc4vci/token`,
        credential_endpoint: `${exchangeId}/oidc4vci/credential`
      };
      res.json(oauth2Config);
    }));

  // an authorization server endpoint
  // serves JWKs associated with each exchange; JWKs are stored with the
  // exchanger used to create the exchange
  app.get(
    routes.jwks,
    cors(),
    getExchange,
    asyncHandler(async (req, res) => {
      const {exchange} = await req.exchange;
      if(!exchange.oidc4vci) {
        // FIXME: improve error
        // unsupported protocol for the exchange
        throw new Error('unsupported protocol');
      }
      // serve exchange's public key
      res.json({keys: [exchange.oidc4vci.oauth2.keyPair.publicKeyJwk]});
    }));

  // an authorization server endpoint
  // handles pre-authorization code exchange for access token; only supports
  // pre-authorization code grant type
  app.options(routes.token, cors());
  app.post(
    routes.token,
    cors(),
    urlencoded,
    validate({bodySchema: oidc4vciTokenBody}),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      const exchangeRecord = await req.exchange;
      const {exchange} = exchangeRecord;
      if(!exchange.oidc4vci) {
        // FIXME: improve error
        // unsupported protocol for the exchange
        throw new Error('unsupported protocol');
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

      const {
        grant_type: grantType,
        'pre-authorized_code': preAuthorizedCode,
        //user_pin: userPin
      } = req.body;

      if(grantType !== PRE_AUTH_GRANT_TYPE) {
        // unsupported grant type
        // FIXME: throw proper oauth2 formatted error
        throw new Error('unsupported grant type');
      }

      // validate grant type
      const {oidc4vci: {preAuthorizedCode: expectedCode}} = exchange;
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
      const {config: exchanger} = req.serviceObject;
      const {accessToken, ttl} = await _createExchangeAccessToken(
        {exchanger, exchangeRecord});

      // send response
      const body = {
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: ttl
      };
      res.json(body);
    }));

  // a credential delivery server endpoint
  // receives a credential request and returns VCs
  app.options(routes.credential, cors());
  app.post(
    routes.credential,
    cors(),
    validate({bodySchema: oidc4vciCredentialBody}),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      /* Clients must POST, e.g.:
      POST /credential HTTP/1.1
      Host: server.example.com
      Content-Type: application/json
      Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

      {
        "type": "https://did.example.org/healthCard"
        "format": "ldp_vc",
        "did": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "proof": {
          "proof_type": "jwt",
          "jwt": "eyJra...nOzM"
        }
      }
      */
      const {config: exchanger} = req.serviceObject;
      const exchangeRecord = await req.exchange;
      const {exchange} = exchangeRecord;
      if(!exchange.oidc4vci) {
        // FIXME: improve error
        // unsupported protocol for the exchange
        throw new Error('unsupported protocol');
      }

      // ensure oauth2 access token is valid
      await _checkAuthz({req, exchanger, exchange});

      // process exchange step if present
      if(exchange.step) {
        const step = exchanger.steps[exchange.step];

        // handle JWT DID Proof request; if step requires it, then `proof` must
        // be in the credential request
        if(step.jwtDidProofRequest) {
          // if no proof is in the body...
          if(!req?.body?.proof?.jwt) {
            return _requestDidProof({res, exchangeRecord});
          }
          // verify the DID proof
          const {body: {proof: {jwt}}} = req;
          const {did} = await verifyDidProofJwt({exchanger, exchange, jwt});
          // add `did` to exchange variables
          exchange.variables[exchange.step] = {did};
        }
      }

      // FIXME: complete exchange; decide what the best recovery path is if
      // delivery fails (but no replay attack detected) after exchange has
      // been marked complete
      //await exchanges.complete()

      // issue VCs
      const {verifiablePresentation} = await issue({exchanger, exchange});

      // send VC
      res.json({
        format: 'ldp_vc',
        /* Note: OIDC4VCI only supports sending a single VC; assume here that
        the exchanger is configured to only allow OIDC4VCI when a single
        VC is being issued. */
        credential: verifiablePresentation.verifiableCredential[0]
      });
    }));
}

async function _createExchangeAccessToken({exchanger, exchangeRecord}) {
  // FIXME: set `exp` to max of 15 minutes / configured max minutes
  const expires = exchangeRecord.meta.expires;
  const exp = Math.floor(expires.getTime() / 1000);

  // create access token
  // FIXME: allow per-service-object-instance agent via `signer` and custom
  // JWT signer code instead?
  const {exchange} = exchangeRecord;
  const {oidc4vci: {oauth2: {keyPair: {privateKeyJwk}}}} = exchange;
  const exchangeId = `${exchanger.id}/exchanges/${exchange.id}`;
  const {accessToken, ttl} = await _createOAuth2AccessToken({
    privateKeyJwk, audience: exchangeId, action: 'write', target: exchangeId,
    exp, iss: exchangeId
  });
  return {accessToken, ttl};
}

async function _createOAuth2AccessToken({
  privateKeyJwk, audience, action, target, exp, iss, nbf, typ = 'at+jwt'
}) {
  const scope = `${action}:${target}`;
  const builder = new SignJWT({scope})
    .setProtectedHeader({alg: 'EdDSA', typ})
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
  const key = await importJWK({...privateKeyJwk, alg: 'EdDSA'});
  const accessToken = await builder.sign(key);
  return {accessToken, ttl};
}

async function _checkAuthz({req, exchanger, exchange}) {
  // optional oauth2 options
  const {oauth2} = exchange.oidc4vci;
  const {maxClockSkew} = oauth2;

  // audience is always the `exchangeId` and cannot be configured; this
  // prevents attacks where access tokens could otherwise be generated
  // if the AS keys were compromised; the `exchangeId` must also be known
  const exchangeId = `${exchanger.id}/exchanges/${req.params.exchangeId}`;
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

  /* OIDC4VCI exchanges themselves are not replayable and single-step, so the
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
