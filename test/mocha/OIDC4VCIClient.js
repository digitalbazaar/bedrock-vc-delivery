/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
export class OIDC4VCIClient {
  constructor() {
    // FIXME: implement
    this.accessToken = null;
  }

  // FIXME: optional param includes DID proof ... or API to perform it
  async requestDelivery() {
    // FIXME: client/wallet sends credential request WITHOUT DID proof JWT:

    /* Implemented on DS:
    POST /credential HTTP/1.1
    Host: server.example.com
    Content-Type: application/json
    Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

    {
      "type": "https://did.example.org/healthCard"
      "format": "ldp_vc"
    }
    */

    // FIXME: if DID authn is required, delivery server sends:
    /*
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

    // FIXME: wallet builds DID proof JWT:
    /*
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
    return {
      format: 'ldp_vc',
      credential: {}
    };
  }

  // FIXME: create a client from a pre-authorized code
  static async fromPreAuthorizedCode({url} = {}) {
    // FIXME: client/wallet gets access token
    /* Implemented on AS:
    POST /token HTTP/1.1
      Host: server.example.com
      Content-Type: application/x-www-form-urlencoded
      Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
      grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
      &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
      &user_pin=493536
    */

    // FIXME: token response (success); note do not send `c_nonce*` here
    // because it conflates AS with DS (delivery server)
    /*
    HTTP/1.1 200 OK
      Content-Type: application/json
      Cache-Control: no-store

      {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
        "token_type": "bearer",
        "expires_in": 86400
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

    // FIXME: store access token in created instance
    const client = new OIDC4VCIClient();
    client.accessToken = 'FIXME';
    return client;
  }

  static async fromAuthorizationCode({url} = {}) {
    // FIXME: client / wallet gets access token
    /*
    POST /token HTTP/1.1
      Host: server.example.com
      Content-Type: application/x-www-form-urlencoded
      Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
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
}
