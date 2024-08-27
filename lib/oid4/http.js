/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as oid4vci from './oid4vci.js';
import * as oid4vp from './oid4vp.js';
import {
  openIdAuthorizationResponseBody,
  openIdBatchCredentialBody,
  openIdCredentialBody,
  openIdTokenBody
} from '../../schemas/bedrock-vc-workflow.js';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {UnsecuredJWT} from 'jose';
import {createValidateMiddleware as validate} from '@bedrock/validation';

/* NOTE: Parts of the OID4VCI design imply tight integration between the
authorization server and the credential issuance / delivery server. This
file provides the routes for both and treats them as integrated; supporting
the OID4VCI pre-authz code flow only as a result. However, we also try to
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
credential endpoint. This error follows the OID4VCI spec and avoids this
particular tight coupling.

Other tight couplings cannot be avoided at this time -- such as the fact that
the credential endpoint is specified in the authorization server's metadata;
this creates challenges for SaaS based solutions and for issuers that want to
use multiple different Issuance / Delivery server backends. We solve these
challenges by using the "pre-authorized code" flows and effectively
instantiating a new authorization server instance per VC exchange. */

// creates OID4VCI Authorization Server + Credential Delivery Server
// endpoints for each individual exchange
export async function createRoutes({
  app, exchangeRoute, getConfigMiddleware, getExchange
} = {}) {
  const openIdRoute = `${exchangeRoute}/openid`;
  const routes = {
    // OID4VCI routes
    asMetadata1: `/.well-known/oauth-authorization-server${exchangeRoute}`,
    asMetadata2: `${exchangeRoute}/.well-known/oauth-authorization-server`,
    ciMetadata1: `/.well-known/openid-credential-issuer${exchangeRoute}`,
    ciMetadata2: `${exchangeRoute}/.well-known/openid-credential-issuer`,
    batchCredential: `${openIdRoute}/batch_credential`,
    credential: `${openIdRoute}/credential`,
    credentialOffer: `${openIdRoute}/credential-offer`,
    token: `${openIdRoute}/token`,
    jwks: `${openIdRoute}/jwks`,
    // OID4VP routes
    authorizationRequest: `${openIdRoute}/client/authorization/request`,
    authorizationResponse: `${openIdRoute}/client/authorization/response`
  };

  // urlencoded body parser
  const urlencodedSmall = bodyParser.urlencoded({
    // (extended=true for rich JSON-like representation)
    extended: true
  });
  const urlencodedLarge = bodyParser.urlencoded({
    // (extended=true for rich JSON-like representation)
    extended: true,
    // allow larger payloads
    limit: '10MB'
  });

  /* Note: The well-known metadata paths for the OID4VCI spec have been
  specified in at least two different ways over time, including
  `<path>/.well-known/...` and `/.well-known/.../<path>`, so they are provided
  here using both approaches to maximize interoperability with clients. It
  is also notable that some versions of the spec have indicated that the
  credential issuer metadata should be expressed in the authorization server
  metadata and others have indicated that they can be separate; since our
  approach virtualizes both the AS and CI anyway, it is all served together. */

  // an authorization server meta data endpoint
  // serves `.well-known` oauth2 AS config for each exchange; each config is
  // based on the workflow used to create the exchange
  app.get(
    routes.asMetadata1,
    cors(),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      res.json(await oid4vci.getAuthorizationServerConfig({req}));
    }));

  // an authorization server meta data endpoint
  // serves `.well-known` oauth2 AS config for each exchange; each config is
  // based on the workflow used to create the exchange
  app.get(
    routes.asMetadata2,
    cors(),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      res.json(await oid4vci.getAuthorizationServerConfig({req}));
    }));

  // a credential issuer meta data endpoint
  // serves `.well-known` oauth2 AS / CI config for each exchange; each config
  // is based on the workflow used to create the exchange
  app.get(
    routes.ciMetadata1,
    cors(),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      res.json(await oid4vci.getCredentialIssuerConfig({req}));
    }));

  // a credential issuer meta data endpoint
  // serves `.well-known` oauth2 AS / CI config for each exchange; each config
  // is based on the workflow used to create the exchange
  app.get(
    routes.ciMetadata2,
    cors(),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      res.json(await oid4vci.getCredentialIssuerConfig({req}));
    }));

  // an authorization server endpoint
  // serves JWKs associated with each exchange; JWKs are stored with the
  // workflow used to create the exchange
  app.get(
    routes.jwks,
    cors(),
    getExchange,
    asyncHandler(async (req, res) => {
      // serve exchange's public key(s)
      const keys = await oid4vci.getJwks({req});
      res.json({keys});
    }));

  // an authorization server endpoint
  // handles pre-authorization code exchange for access token; only supports
  // pre-authorization code grant type
  app.options(routes.token, cors());
  app.post(
    routes.token,
    cors(),
    urlencodedSmall,
    validate({bodySchema: openIdTokenBody}),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      const response = await oid4vci.processAccessTokenRequest({req, res});
      res.json(response);
    }));

  // a credential delivery server endpoint
  // receives a credential request and returns VCs
  app.options(routes.credential, cors());
  app.post(
    routes.credential,
    cors(),
    validate({bodySchema: openIdCredentialBody}),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      /* Clients must POST, e.g.:
      POST /credential HTTP/1.1
      Host: server.example.com
      Content-Type: application/json
      Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

      {
        "format": "ldp_vc",
        "credential_definition": {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
          ],
          "type": [
            "VerifiableCredential",
            "UniversityDegreeCredential"
          ]
        },
        "did": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "proof": {
          "proof_type": "jwt",
          "jwt": "eyJra...nOzM"
        }
      }
      */
      const result = await oid4vci.processCredentialRequests({
        req, res, isBatchRequest: false
      });
      if(!result) {
        // DID proof request response sent
        return;
      }

      /* Note: The `/credential` route only supports sending a single VC;
      assume here that this workflow is configured for a single VC and an
      error code would have been sent to the client to use the batch
      endpoint if there was more than one VC to deliver. */
      const {response, format} = result;
      const {verifiablePresentation: {verifiableCredential: [vc]}} = response;

      // parse any enveloped VC
      let credential;
      if(vc.type === 'EnvelopedVerifiableCredential' &&
        vc.id?.startsWith('data:application/jwt,')) {
        credential = vc.id.slice('data:application/jwt,'.length);
      } else {
        credential = vc;
      }

      // send OID4VCI response
      res.json({
        // FIXME: this doesn't seem to be in the spec anymore (draft 14+)...
        format,
        credential
      });
    }));

  // a credential delivery server endpoint
  // serves the credential offer for all possible credentials in the exchange
  app.get(
    routes.credentialOffer,
    cors(),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      const offer = await oid4vci.getCredentialOffer({req});
      res.json(offer);
    }));

  // a batch credential delivery server endpoint
  // receives N credential requests and returns N VCs
  app.options(routes.batchCredential, cors());
  app.post(
    routes.batchCredential,
    cors(),
    validate({bodySchema: openIdBatchCredentialBody}),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      /* Clients must POST, e.g.:
      POST /batch_credential HTTP/1.1
      Host: server.example.com
      Content-Type: application/json
      Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

      {
        credential_requests: [{
          "format": "ldp_vc",
          "credential_definition": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
              "VerifiableCredential",
              "UniversityDegreeCredential"
            ]
          },
          "did": "did:example:ebfeb1f712ebc6f1c276e12ec21",
          "proof": {
            "proof_type": "jwt",
            "jwt": "eyJra...nOzM"
          }
        }]
      }
      */
      const result = await oid4vci.processCredentialRequests({
        req, res, isBatchRequest: true
      });
      if(!result) {
        // DID proof request response sent
        return;
      }

      // send VCs
      const {response: {verifiablePresentation}, format} = result;
      // FIXME: "format" doesn't seem to be in the spec anymore (draft 14+)...
      const responses = verifiablePresentation.verifiableCredential.map(vc => {
        // parse any enveloped VC
        let credential;
        if(vc.type === 'EnvelopedVerifiableCredential' &&
          vc.id?.startsWith('data:application/jwt,')) {
          credential = vc.id.slice('data:application/jwt,'.length);
        } else {
          credential = vc;
        }
        return {format, credential};
      });
      res.json({credential_responses: responses});
    }));

  // an OID4VP verifier endpoint
  // serves the authorization request, including presentation definition
  // associated with the current step in the exchange
  app.get(
    routes.authorizationRequest,
    cors(),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      const {
        authorizationRequest
      } = await oid4vp.getAuthorizationRequest({req});
      // construct and send authz request as unsecured JWT
      const jwt = new UnsecuredJWT(authorizationRequest).encode();
      res.set('content-type', 'application/oauth-authz-req+jwt');
      res.send(jwt);
    }));

  // an OID4VP verifier endpoint
  // receives an authorization response with vp_token
  app.options(routes.authorizationResponse, cors());
  app.post(
    routes.authorizationResponse,
    cors(),
    urlencodedLarge,
    validate({bodySchema: openIdAuthorizationResponseBody()}),
    getConfigMiddleware,
    getExchange,
    asyncHandler(async (req, res) => {
      const result = await oid4vp.processAuthorizationResponse({req});
      res.json(result);
    }));
}
