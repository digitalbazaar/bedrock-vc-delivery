/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {asyncHandler} from '@bedrock/express';

const {config} = bedrock;

// FIXME: change to expose functions to create services that can be called
// by the top level application -- and to mount the AS / credential issuance
// endpoints appropriately
// bedrock.events.on('bedrock-express.configure.routes', app => {
// });

// FIXME: method for adding credential routes; ensure that route servicing
// /exchangers/z1...2/exchanges/z3...4/oidc4vci/credential will not hit
// /exchangers/z1...2/exchanges middleware
// FIXME: exchange must indicate the authorization server URL; include a
// cache for AS metadata
export async function create({app} = {}) {
  // FIXME: pass in base route instead; do not use config
  const {routes} = config['vc-delivery'];

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
  // 3. post the received authorization code to receive an access code (NOTE:
  //    we do not ever send the optional `c_nonce` that must be signed in a
  //    DID authn proof here, but rather defer that to an error case later
  //    for architectural separation of concerns)
  // 4. Send the credential request along with the access token and either
  //    receive the VC or, optionally, receive an error with a `c_nonce`
  // 5. Sign over the `c_nonce` (create a JWT DID proof)
  // 6. Send the JWT DID proof in a credential request along with the access
  //    token in the header to the VC delivery endpoint and receive the VC

  // FIXME: NOTE: parts of OIDC4VCI design would imply requiring tight
  // integration between the AS and the issuance / delivery server; we do not
  // implement those paths here (i.e., we do not return any `c_nonce` from the
  // AS in exchange for an authz code, rather we use the other suggestion from
  // the spec to send an error response to the initial credential request that
  // includes the `c_nonce` such that it is generated and handled by the
  // delivery server instead of the AS); also, the AS only implements
  // client-discovery -- avoiding the need to store client registrations

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

  // FIXME: implemented on DS (delivery server) aka RS (resource server)
  app.post(
    // FIXME: include `/exchangers/z1..2/exchanges/z3...4/` in base path
    routes.basePath + '/credential',
    asyncHandler(async (req, res) => {
      // FIXME: if the same exchange can be serviced by *either* OIDC4VCI or
      // VC-API, then this will need to become a middleware / callable function
      // that will be triggered based on a route path or query param indicating
      // the desired protocol

      // FIXME: get both exchanger and exchange in parallel from database;
      // the exchanger can be cached, but do not cache the exchange for now

      // FIXME: if exchanger supports OIDC4VCI, then its record must include
      // the AS issuer URL for delivery (which might be a different one from
      // other oauth2 access on the exchanger itself)

      // FIXME: some refactoring with bedrock-vc-exchanger will be required;
      // additional use case to consider is credential refresh which requires
      // a longer exchange TTL (as long as the VC can be refreshed which may
      // be months vs. just minutes for VC delivery)

      // FIXME: exchange data must include AS issuer URL
      // FIXME: use AS issuer URL to get meta data (include cache for this
      // and see if `bedrock-service-core/lib/oauth2.js` can be reused) and
      // check access token, etc.
      // FIXME: if exchange data requires DID authn and no DID proof is in
      // the request, send a DID proof error w/newly generated c_nonce;
      // FIXME: add a database to store `c_nonce`s -- or append them to the
      // exchange data? they must expire at the same time as the exchange and
      // be short-lived generally
      // FIXME: check DID proof, if invalid, send error response -- with new
      // `c_nonce`? seems like the error response needs to be more clear based
      // on the type of error, i.e., what is the proof algorithm to be used?
      // Note: any discovery so far has been around the AS, how does the client
      // know which DID auth proof algorithm it can use with the DS?
      // FIXME: process any VC templates w/ new received DID (what about
      // multiple DIDs?)
      // FIXME: send generated VCs to issuer service (zcaps or target URLs
      // specified in the exchange data)... get credentials from the service
      // agent associated with the config? assume this endpoint is mounted
      // such that there is a service config that can be retrieved? ...
      // if this is mounted on a service endpoint, do we assume that there's
      // no security for hitting the root service endpoint? ... that is
      // different from `bedrock-service-core`
      // FIXME: return encrypted and / or issued VCs

      // FIXME: if the exchange requires a proof, use verifier API to get
      // a challenge and return it to the client ... perhaps also store the
      // challenge? process:
      // 1. when the exchange is created, get a challenge and store it at that
      //   time ... and store it and its expiration time; if it has expired
      //   when the client asks for it, get a new one on demand, otherwise
      //   do not; do not allow the client to ask for more than N challenges,
      //   as this is an attack vector

      // FIXME: expect request body:
      /*
      {
        "type": "https://did.example.org/healthCard"
        "format": "ldp_vc"
      }
      */
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
      } else {
        res.json({
          format: 'ldp_vc',
          credential: {}
        });
      }
    }));
}