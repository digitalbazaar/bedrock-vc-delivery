/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import {checkAccessToken} from '@bedrock/oauth2-verifier';
import {importJWK, SignJWT} from 'jose';
import {issue} from './issue.js';
import {timingSafeEqual} from 'node:crypto';

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

  // urlencoded body parser (extended=true for rich JSON-like representation)
  const urlencoded = bodyParser.urlencoded({extended: true});

  // an authorization server endpoint
  // serves `.well-known` oauth2 AS config for each exchange; each config is
  // based on the exchanger used to create the exchange
  app.get(
    `/.well-known/oauth-authorization-server${exchangeRoute}`,
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
      // FIXME: remove me
      console.log('oauth2Config', oauth2Config);
      res.json(oauth2Config);
    }));

  // an authorization server endpoint
  // serves JWKs associated with each exchange; JWKs are stored with the
  // exchanger used to create the exchange
  app.get(
    `${oidc4vciRoute}/jwks`,
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
  app.post(
    `${oidc4vciRoute}/token`,
    getConfigMiddleware,
    getExchange,
    urlencoded,
    asyncHandler(async (req, res) => {
      const exchangeRecord = await req.exchange;
      const {exchange} = exchangeRecord;
      if(!exchange.oidc4vci) {
        // FIXME: improve error
        // unsupported protocol for the exchange
        throw new Error('unsupported protocol');
      }

      console.log('/token request body', req.body);
      const {
        grant_type: grantType,
        'pre-authorized_code': preAuthorizedCode,
        //user_pin: userPin
      } = req.body;

      // validate grant type
      const {oidc4vci: {preAuthorizedCode: expectedCode}} = exchange;
      if(expectedCode) {
        if(grantType !== PRE_AUTH_GRANT_TYPE) {
          // unsupported grant type
          // FIXME: throw proper oauth2 formatted error
          throw new Error('unsupported grant type');
        }

        // ensure expected pre-authz code and user PIN match
        // FIXME: check `userPin` too
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

      // pre-authz code request:
      // grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
      // &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
      // &user_pin=493536
      const body = {
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: ttl
      };
      console.log('sending access token response', body);
      res.json(body);

      // OR:

      // authz code request:
      // grant_type=authorization_code
      // &code=SplxlOBeZQQYbYS6WxSbIA
      // &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
      // &redirect_uri=https%3A%2F%2FWallet.example.org%2Fcb
    }));

  // a credential delivery server endpoint
  // receives a credential request and returns VCs
  app.post(
    `${oidc4vciRoute}/credential`,
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      const {config: exchanger} = req.serviceObject;
      const {exchange} = await req.exchange;
      if(!exchange.oidc4vci) {
        // FIXME: improve error
        // unsupported protocol for the exchange
        throw new Error('unsupported protocol');
      }

      // ensure oauth2 access token is valid
      await _checkAuthz({req, exchanger, exchange});

      // FIXME: check current step in `exchange` ... if there is no step
      // then DID Authn is not possible

      // FIXME: check for `jwtDidProofRequest` and `generateChallenge` in the
      // step from the exchanger

      const result = {};

      // FIXME: for OIDC4VCI, clients must POST to:
      // /exchangers/<exchangerId>/exchanges/<exchangeId>/oidc4vci/credential
      // ...payload must be an OIDC4VCI credential request:
      /*
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
          "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
          xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
          0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbm
          NlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
        }
      }
      */

      // OR, without a DID proof:

      /*
      {
        "type": "https://did.example.org/healthCard"
        "format": "ldp_vc"
      }
      */

      // FIXME: if the exchange requires a proof, use verifier API to get
      // a challenge and return it to the client; ideally we can fully use
      // challenge management via the verifier -- only consider storing the
      // challenge to avoid requesting multiple challenges from the verifier
      // if necessary to avoid surcharges

      // FIXME: `9.4 Credential Issuer-provided nonce` allows the credential
      // ...issuer infrastructure to provide the nonce via an error:
      /* HTTP/1.1 400 Bad Request
      Content-Type: application/json
      Cache-Control: no-store

      {
        "error": "invalid_or_missing_proof"
        "error_description":
            "Credential issuer requires proof element in Credential Request"
        "c_nonce": "8YE9hCnyV2",
        "c_nonce_expires_in": 86400
      }*/

      // FIXME: *if* exchange requires DID authn, then make sure a proof
      // is present
      if(!req.body.proof) {
        res.status(400).json({
          error: 'invalid_or_missing_proof',
          error_description:
            'Credential issuer requires proof element in Credential Request',
          // FIXME: use verifier API to get a challenge
          c_nonce: '8YE9hCnyV2',
          // FIXME: determine expiration period
          c_nonce_expires_in: 86400
        });
        return;
      }

      // FIXME: complete exchange; decide what the best recovery path is if
      // delivery fails (but no replay attack detected) after exchange has
      // been marked complete

      // issue VCs
      console.log('processing exchange', exchange);
      const {verifiablePresentation} = await issue({exchanger, exchange});

      // send VC
      res.json({
        format: 'ldp_vc',
        // FIXME: OIDC4VCI only supports sending a single VC; assume that
        // the exchanger is configured to only allow OIDC4VCI when a single
        // VC is being issued
        credential: verifiablePresentation.verifiableCredential[0]
      });
    }));
}

async function _createExchangeAccessToken({exchanger, exchangeRecord}) {
  // FIXME: set `exp` to max of 15 minutes / configured max minutes
  const expires = exchangeRecord.meta.expires;
  const exp = Math.floor(expires.getTime() / 1000);

  // create access token
  // FIXME: TBD location of key pair
  // FIXME: allow per-service-object-instance agent via `signer` and custom
  // JWT signer code instead
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
