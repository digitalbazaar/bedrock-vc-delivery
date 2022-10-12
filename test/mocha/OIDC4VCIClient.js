/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {httpClient} from '@digitalbazaar/http-client';

// FIXME: remove me; temporary for testing
import {jwtVerify} from 'jose';

const TEXT_ENCODER = new TextEncoder();
const ENCODED_PERIOD = TEXT_ENCODER.encode('.');

const GRANT_TYPES = new Map([
  ['preAuthorizedCode', 'urn:ietf:params:oauth:grant-type:pre-authorized_code']
])
const HEADERS = {accept: 'application/json'};
const WELL_KNOWN_REGEX = /\/\.well-known\/([^\/]+)/;

// FIXME: move to separate lib
export class OIDC4VCIClient {
  constructor({accessToken = null, agent, issuerConfig} = {}) {
    this.accessToken = accessToken;
    this.agent = agent;
    this.issuerConfig = issuerConfig;
  }

  // FIXME: optional param includes DID proof
  async requestDelivery({didProof, agent} = {}) {
    try {
      /* First send credential request to DS without DID proof JWT, e.g.:

      POST /credential HTTP/1.1
      Host: server.example.com
      Content-Type: application/json
      Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

      {
        "type": "https://did.example.org/healthCard"
        "format": "ldp_vc"
      }
      */
      const {credential_endpoint: url} = this.issuerConfig;

      let result;
      try {
        const response = await httpClient.post(url, {agent, headers: HEADERS});
        result = response.data;
        if(!result) {
          const error = new Error('Credential response format is not JSON.');
          error.name = 'DataError';
          throw error;
        }
      } catch(cause) {
        if(!_isMissingProofError(cause)) {
          // non-specific error case
          throw cause;
        }

        const {data: details} = cause.response;
        const error = new Error('');
        error.name = 'NotAllowedError';
        error.cause = cause;
        error.details = details;
        throw error;
      }

      // FIXME: wallet builds DID proof JWT:
      /*const jwt = await OIDC4VCIClient.generateDIDProofJWT(
        {signer, nonce, iss, aud, nonce, exp, nbf});*/

      // FIXME: wallet resends credential request w/ DID proof JWT:

      /* Implemented on DS:
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

      // FIXME: wallet receives credential:
      // FIXME: Note! The credential is not wrapped here in a VP in the current
      // ...spec:

      /*
      HTTP/1.1 200 OK
        Content-Type: application/json
        Cache-Control: no-store

      {
        "format": "ldp_vc"
        "credential" : {...}
      }
      */
      return result;
    } catch(cause) {
      console.log('cause', cause);
      const error = new Error('Could not receive credentials.');
      error.name = 'OperationError';
      error.cause = cause;
      throw error;
    }
  }

  // FIXME: move to helper function in separate lib
  static async discoverIssuer({issuerConfigUrl, agent} = {}) {
    try {
      if(!(issuerConfigUrl && typeof issuerConfigUrl === 'string')) {
        throw new TypeError('"issuerConfigUrl" must be a string.');
      }

      // FIXME: allow these params to be passed / configured
      const fetchOptions = {
        // max size for issuer config related responses (in bytes, ~4 KiB)
        size: 4096,
        // timeout in ms for fetching an issuer config
        timeout: 5000,
        agent
      };

      // FIXME: needs a rolling, memoized cache
      console.log('issuerConfigUrl', issuerConfigUrl);
      const response = await httpClient.get(issuerConfigUrl, fetchOptions);
      if(!response.data) {
        const error = new Error('Issuer configuration format is not JSON.');
        error.name = 'DataError';
        throw error;
      }

      const {data: config} = response;
      const {issuer, token_endpoint} = config;

      // validate `issuer`
      if(!(typeof issuer === 'string' && issuer.startsWith('https://'))) {
        const error = new Error('"issuer" is not an HTTPS URL.');
        error.name = 'DataError';
        throw error;
      }

      /* Validate `issuer` value against `issuerConfigUrl` (per RFC 8414):

      The `origin` and `path` element must be parsed from `issuer` and checked
      against `issuerConfigUrl` like so:

      For issuer `<origin>` (no path), `issuerConfigUrl` must match:
      `<origin>/.well-known/<any-path-segment>`

      For issuer `<origin><path>`, `issuerConfigUrl` must be:
      `<origin>/.well-known/<any-path-segment><path>` */
      const {pathname: wellKnownPath} = new URL(issuerConfigUrl);
      const anyPathSegment = wellKnownPath.match(WELL_KNOWN_REGEX)[1];
      const {origin, pathname} = new URL(issuer);
      let expectedConfigUrl = `${origin}/.well-known/${anyPathSegment}`;
      if(pathname !== '/') {
        expectedConfigUrl += pathname;
      }
      if(issuerConfigUrl !== expectedConfigUrl) {
        const error = new Error('"issuer" does not match configuration URL.');
        error.name = 'DataError';
        throw error;
      }

      // ensure `token_endpoint` is valid
      if(!(token_endpoint && typeof token_endpoint === 'string')) {
        const error = new TypeError('"token_endpoint" must be a string.');
        error.name = 'DataError';
        throw error;
      }

      return config;
    } catch(cause) {
      const error = new Error('Could not get OAuth2 issuer configuration.');
      error.name = 'OperationError';
      error.cause = cause;
      throw error;
    }
  }

  // FIXME: create a client from a pre-authorized code
  // FIXME: determine params to be passed into this function
  static async fromPreAuthorizedCode({
    issuer, preAuthorizedCode, userPin, agent
  } = {}) {
    try {
      // discover issuer info
      const issuerConfigUrl =
        `${issuer}/.well-known/oauth-authorization-server`;
      const issuerConfig = await OIDC4VCIClient.discoverIssuer(
        {issuerConfigUrl, agent});
      console.log('issuerConfig', issuerConfig);

      /* First get access token from AS (Authorization Server), e.g.:

      POST /token HTTP/1.1
        Host: server.example.com
        Content-Type: application/x-www-form-urlencoded
        grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
        &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
        &user_pin=493536

      Note a bad response would look like:

      /*
      HTTP/1.1 400 Bad Request
      Content-Type: application/json
      Cache-Control: no-store
      {
        "error": "invalid_request"
      }
      */
      const body = new URLSearchParams();
      body.set('grant_type', GRANT_TYPES.get('preAuthorizedCode'));
      body.set('pre-authorized_code', preAuthorizedCode);
      // `user_pin` is optional
      if(userPin !== undefined) {
        body.set('user_pin', userPin);
      }
      const {token_endpoint} = issuerConfig;
      const response = await httpClient.post(token_endpoint, {
        agent, body, headers: HEADERS
      });
      const {data: result} = response;
      if(!result) {
        const error = new Error(
          'Could not get access token; response is not JSON.');
        error.name = 'DataError';
        throw error;
      }

      /* Validate response body (Note: Do not check or use `c_nonce*` here
      because it conflates AS with DS (Delivery Server)), e.g.:

      HTTP/1.1 200 OK
        Content-Type: application/json
        Cache-Control: no-store

        {
          "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
          "token_type": "bearer",
          "expires_in": 86400
        }
      */
      const {access_token: accessToken, token_type} = result;
      if(!(accessToken && typeof accessToken === 'string')) {
        const error = new Error(
          'Invalid access token response; "access_token" must be a string.');
        error.name = 'DataError';
        throw error;
      }
      if(token_type !== 'bearer') {
        const error = new Error(
          'Invalid access token response; "token_type" must be a "bearer".');
        error.name = 'DataError';
        throw error;
      }

      // create client w/access token
      return new OIDC4VCIClient({accessToken, agent, issuerConfig});
    } catch(cause) {
      const error = new Error('Could not create OIDC4VCI client.');
      console.log('cause', cause);
      error.name = 'OperationError';
      error.cause = cause;
      throw error;
    }
  }

  static async fromAuthorizationCode({url, agent} = {}) {
    /* First get access token from AS:

    POST /token HTTP/1.1
      Host: server.example.com
      Content-Type: application/x-www-form-urlencoded
      grant_type=authorization_code
      &code=SplxlOBeZQQYbYS6WxSbIA
      &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
      &redirect_uri=https%3A%2F%2FWallet.example.org%2Fcb
    */

    // FIXME: token response (success); note `c_nonce*` probably doesn't make
    // sense to send here because it presumes authz server and issuance server
    // (delivery server) are the same; instead send those (if DID authn is
    // required) from the delivery server
    /*
    HTTP/1.1 200 OK
      Content-Type: application/json
      Cache-Control: no-store

      {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
        "token_type": "bearer",
        "expires_in": 86400,
        "c_nonce": "tZignsnFbp",
        "c_nonce_expires_in": 86400
      }
    */

    // FIXME: token response (failure)
    /*
    HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store
    {
      "error": "invalid_request"
    }
    */

    const client = new OIDC4VCIClient();
    client.accessToken = 'FIXME';
    return client;
  }

  static parseInitiateIssuanceUrl({url} = {}) {
    if(!(url && typeof url === 'string')) {
      throw new TypeError('"url" must be a string.');
    }

    /* Parse URL, e.g.:

    'openid-initiate-issuance://?' +
        'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom' +
        '&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard' +
        '&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA' +
        '&user_pin_required=true';
    */
    const {protocol, searchParams} = new URL(url);
    if(protocol !== 'openid-initiate-issuance:') {
      throw new SyntaxError(
        '"url" must express a URL with the ' +
        '"openid-initiate-issuance" protocol.');
    }

    const issuer = searchParams.get('issuer');
    const credentialType = searchParams.get('credential_type');
    const preAuthorizedCode = searchParams.get('pre-authorized_code');
    const userPinRequired = searchParams.get('user_pin_required') === 'true';
    return {issuer, credentialType, preAuthorizedCode, userPinRequired};
  }

  // FIXME: move to helper function in separate lib
  static async generateDIDProofJWT({signer, nonce, iss, aud, exp, nbf} = {}) {
    /* Example:
    {
      "alg": "ES256",
      "kid":"did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1"
    }.
    {
      "iss": "s6BhdRkqt3",
      "aud": "https://server.example.com",
      "iat": 1659145924,
      "nonce": "tZignsnFbp"
    }
    */

    if(exp === undefined) {
      // default to 5 minute expiration time
      exp = Math.floor(Date.now() / 1000) + 60 * 5;
    }
    if(nbf === undefined) {
      // default to now
      nbf = Math.floor(Date.now() / 1000);
    }

    const {algorithm: alg, id: kid} = signer;
    const payload = {nonce, iss, aud, exp, nbf};
    const protectedHeader = {alg, kid};

    return _signJWT({payload, protectedHeader, signer});
  }
}

function _isMissingProofError(error) {
  /* If DID authn is required, delivery server sends, e.g.:

  HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store

  {
    "error": "invalid_or_missing_proof"
    "error_description":
        "Credential issuer requires proof element in Credential Request"
    "c_nonce": "8YE9hCnyV2",
    "c_nonce_expires_in": 86400
  }
  */
  return error.status === 400 &&
    error?.response?.data?.error === 'invalid_or_missing_proof';
}

async function _signJWT({payload, protectedHeader, signer} = {}) {
  // encode payload and protected header
  const b64Payload = base64url.encode(JSON.stringify(payload));
  const b64ProtectedHeader = base64url.encode(JSON.stringify(protectedHeader));
  payload = TEXT_ENCODER.encode(b64Payload);
  protectedHeader = TEXT_ENCODER.encode(b64ProtectedHeader);

  // concatenate
  const data = new Uint8Array(
    protectedHeader.length + ENCODED_PERIOD.length + payload.length);
  data.set(protectedHeader);
  data.set(ENCODED_PERIOD, protectedHeader.length);
  data.set(payload, protectedHeader.length + ENCODED_PERIOD.length);

  // sign
  const signature = await signer.sign(data);

  // create JWS
  const jws = {
    signature: base64url.encode(signature),
    payload: b64Payload,
    protected: b64ProtectedHeader
  };

  // create compact JWT
  return `${jws.protected}.${jws.payload}.${jws.signature}`;
}
