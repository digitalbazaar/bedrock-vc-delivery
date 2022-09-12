/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {asyncHandler} from '@bedrock/express';

const {config} = bedrock;

bedrock.events.on('bedrock-express.configure.routes', app => {
  const {routes} = config['vc-delivery'];
  app.post(
    routes.basePath,
    asyncHandler(async (/*req, res*/) => {
    }));

  // FIXME: clients must POST to:
  // /exchangers/<exchangerId>/exchanges/<exchangeId>
  // ...the HTTP endpoint must fetch the exchange and see the protocol;
  // ...if it is VC-API, then the data in the payload must have
  // ...`verifiablePresentation` with a VP in it;
  // ...if it is OIDC4VCI, then the data in the payload must be an OIDC4VCI
  // ...credential request:
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

  // FIXME: for OIDC4VCI, a wallet must:
  // 1. hit an endpoint to ask for the URL to get an authorization code using
  //    either a pre-auth grant type or a user-mediated authz grant type
  // 2. send the user to the endpoint for the authorization code (optional
  //    based on grant type)
  // 3. post the received authorization code to receive an access code AND,
  //    optionally, a `c_nonce` that must be signed in a DID authn proof
  // 4. Sign over the `c_nonce` (create a JWT DID proof)
  // 5. Send the JWT DID proof in a credential request along with the access
  //    token in the header to the VC delivery endpoint

  // FIXME: NOTE: because of OIDC4VCI design... the whole AS needs to be
  // essentially integrated with the issuance / delivery server, so implement
  // the endpoint for getting an authz code, an endpoint for exchanging it for
  // an access token and a `c_nonce`, the endpoint for receiving the credential
  // request (along with DID JWT signature over the `c_nonce`), and the
  // dynamic wallet registration endpoint; make it possible for wallet
  // registrations to expire rather quickly (but no more quickly than an
  // access token -- and "refresh" registrations when a new access token is
  // requested if the wallet registration has not expired yet)

  // FIXME: implement credential type endpoint (step 1 above for a wallet)
  // as something that lives off of `/exchangers/<exchangerId>/oidc4vci/???`
  // ...it responds with an authorization URL to redirect the user to -- the
  // ...result of the user authzing the wallet will be the authz code being
  // ...sent to the wallet's redirect URL;
  // ...if the pre-authz flow is used, then the pre-authz code will be included
  // ...directly in a CHAPI / QR code request that the wallet receives; the
  // ...wallet can send that pre-authz code directly for the access token and
  // ...`c_nonce`
  // ...since the authz server provides the `c_nonce`, it will need to check
  // ...it for replays and will need to be responsible for validating the DID
  // ...proof in some way
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
  // ...we should use this instead... it would always need to be implemented
  // ...anyway -- so we should remove the option to have it sent by the authz
  // ...server, which might be separated from the credential issuer

  // FIXME: determine if each exchange can be its own OpenID provider, serving
  // its own meta-data:
  // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  // GET /issuer1/.well-known/openid-configuration HTTP/1.1
  // Host: example.com
  // ... whereby `issuer1` appears here: `https://example.com/issuer1`
  // ... or really like so:
  // `https://example.com/exchangers/z12...123/exchanges/z64...123123` with:
  // GET /exchangers/z12...123/exchanges/z64...123123/.well-known/openid-...`
  app.post(
    // FIXME: may need this endpoint to
    routes.basePath + '/token',
    asyncHandler(async (/*req, res*/) => {
    }));

});
