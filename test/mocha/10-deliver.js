/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {createRequire} from 'node:module';
import {httpClient} from '@digitalbazaar/http-client';
import {klona} from 'klona';
import {mockData} from './mock.data.js';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;
const serviceType = 'vc-issuer';

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('delivery', () => {
  let capabilityAgent;
  let oauth2IssuerConfig;
  let issuerId;
  let issuerRootZcap;
  const zcaps = {};
  beforeEach(async () => {
    const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
    const handle = 'test';
    capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

    // create keystore for capability agent
    const keystoreAgent = await helpers.createKeystoreAgent(
      {capabilityAgent});

    // generate key for signing VCs (make it a did:key DID for simplicity)
    const assertionMethodKey = await keystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });

    // create EDV for storage (creating hmac and kak in the process)
    const {
      edvConfig,
      hmac,
      keyAgreementKey
    } = await helpers.createEdv({capabilityAgent, keystoreAgent});

    // get service agent to delegate to
    const serviceAgentUrl =
      `${baseUrl}/service-agents/${encodeURIComponent(serviceType)}`;
    const {data: serviceAgent} = await httpClient.get(
      serviceAgentUrl, {agent});

    // delegate edv, hmac, and key agreement key zcaps to service agent
    const {id: edvId} = edvConfig;
    zcaps.edv = await helpers.delegate({
      controller: serviceAgent.id,
      delegator: capabilityAgent,
      invocationTarget: edvId
    });
    const {keystoreId} = keystoreAgent;
    zcaps.hmac = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: hmac.id,
      delegator: capabilityAgent
    });
    zcaps.keyAgreementKey = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: keyAgreementKey.kmsId,
      delegator: capabilityAgent
    });
    zcaps['assertionMethod:ed25519'] = await helpers.delegate({
      capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
      controller: serviceAgent.id,
      invocationTarget: assertionMethodKey.kmsId,
      delegator: capabilityAgent
    });

    // create issuer instance w/ oauth2-based authz
    oauth2IssuerConfig = await helpers.createConfig(
      {capabilityAgent, zcaps, oauth2: true});
    issuerId = oauth2IssuerConfig.id;
    issuerRootZcap = `urn:zcap:root:${encodeURIComponent(issuerId)}`;
  });
  describe('pre-authorized code delivery', () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    // FIXME: handle URL w/pre-authorized_code
    /* Pre-authorized flow, issuer-initiated
    openid-initiate-issuance://?
        issuer=https%3A%2F%2Fserver%2Eexample%2Ecom
        &credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard
        &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
        &user_pin_required=true
    */

    // FIXME: wallet gets access token
    /*
    POST /token HTTP/1.1
      Host: server.example.com
      Content-Type: application/x-www-form-urlencoded
      Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
      grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
      &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
      &user_pin=493536
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

    // FIXME: request delivery (use helpers.requestDelivery() which implements
    // what follows for reuse in other tests...)

    // FIXME: wallet sends credential request WITHOUT DID proof JWT:

    /*
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
  });

  describe('wallet initiated delivery', () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    // FIXME: wallet sends request for a credential
    /*
    {
     "type":"openid_credential",
     "credential_type":"https://did.example.org/healthCard",
     "format":"ldp_vc",
     //"locations": ["aud1", "aud2", ...]
    }
    // ... OR ... request 2+ credentials
    [
      {
          "type":"openid_credential",
          "credential_type":"https://did.example.org/healthCard",
          "format":"ldp_vc"
      },
      {
          "type":"openid_credential",
          "credential_type":"https://did.example.org/mDL"
      }
    ]
    */

    // FIXME: wallet receives response
    /*
    HTTP/1.1 302 Found
    Location: https://server.example.com/authorize?
      response_type=code
      &client_id=s6BhdRkqt3
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
      &authorization_details=%5B%7B%22type%22:%22openid_credential%22,%22credential_type
      %22:%22https://did.example.org/healthCard%22,%22format%22:%22ldp_vc%22%7D,%7B%22ty
      pe%22:%22openid_credential%22,%22credential_type%22:%22https://did.example.org/mDL
      %22%7D%5D
      &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
      });

    ... OR ... scope option (map credential type to an oauth2 scope):

    HTTP/1.1 302 Found
    Location: https://server.example.com/authorize?
      response_type=code
      &scope=com.example.healthCardCredential
      &client_id=s6BhdRkqt3
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
      &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    */

    // FIXME: authorization responses:
    /*
    success:
    HTTP/1.1 302 Found
      Location: https://Wallet.example.org/cb?
        code=SplxlOBeZQQYbYS6WxSbIA

    failure:
    HTTP/1.1 302 Found
    Location: https://client.example.net/cb?
        error=invalid_request
        &error_description=Unsupported%20response_type%20value
    */

    // FIXME: wallet gets access token
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

    // FIXME: request delivery (use helpers.requestDelivery())
  });

  describe('/credentials/issue', () => {
    it('issues a valid credential w/no "credentialStatus"', async () => {
      const credential = klona(mockCredential);
      let error;
      let result;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({
          url: `${issuerId}/credentials/issue`,
          capability: issuerRootZcap,
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      assertNoError(error);
      should.exist(result.data);
      should.exist(result.data.verifiableCredential);
      const {verifiableCredential} = result.data;
      verifiableCredential.should.be.an('object');
      should.exist(verifiableCredential['@context']);
      should.exist(verifiableCredential.id);
      should.exist(verifiableCredential.type);
      should.exist(verifiableCredential.issuer);
      should.exist(verifiableCredential.issuanceDate);
      should.exist(verifiableCredential.credentialSubject);
      verifiableCredential.credentialSubject.should.be.an('object');
      should.not.exist(verifiableCredential.credentialStatus);
      should.exist(verifiableCredential.proof);
      verifiableCredential.proof.should.be.an('object');
    });
    it('fails to issue a valid credential', async () => {
      let error;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        await zcapClient.write({
          url: `${issuerId}/credentials/issue`,
          capability: issuerRootZcap,
          json: {
            credential: {}
          }
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      error.data.type.should.equal('ValidationError');
    });
    it('issues a valid credential w/oauth2 w/root scope', async () => {
      const credential = klona(mockCredential);
      let error;
      let result;
      try {
        const configId = oauth2IssuerConfig.id;
        const url = `${configId}/credentials/issue`;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/'});
        result = await httpClient.post(url, {
          agent,
          headers: {authorization: `Bearer ${accessToken}`},
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      assertNoError(error);
      should.exist(result.data);
      should.exist(result.data.verifiableCredential);
      const {verifiableCredential} = result.data;
      verifiableCredential.should.be.an('object');
      should.exist(verifiableCredential['@context']);
      should.exist(verifiableCredential.id);
      should.exist(verifiableCredential.type);
      should.exist(verifiableCredential.issuer);
      should.exist(verifiableCredential.issuanceDate);
      should.exist(verifiableCredential.credentialSubject);
      verifiableCredential.credentialSubject.should.be.an('object');
      should.not.exist(verifiableCredential.credentialStatus);
      should.exist(verifiableCredential.proof);
      verifiableCredential.proof.should.be.an('object');
    });
    it('issues a valid credential w/oauth2 w/credentials scope', async () => {
      const credential = klona(mockCredential);
      let error;
      let result;
      try {
        const configId = oauth2IssuerConfig.id;
        const url = `${configId}/credentials/issue`;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/credentials'});
        result = await httpClient.post(url, {
          agent,
          headers: {authorization: `Bearer ${accessToken}`},
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      assertNoError(error);
      should.exist(result.data);
      should.exist(result.data.verifiableCredential);
      const {verifiableCredential} = result.data;
      verifiableCredential.should.be.an('object');
      should.exist(verifiableCredential['@context']);
      should.exist(verifiableCredential.id);
      should.exist(verifiableCredential.type);
      should.exist(verifiableCredential.issuer);
      should.exist(verifiableCredential.issuanceDate);
      should.exist(verifiableCredential.credentialSubject);
      verifiableCredential.credentialSubject.should.be.an('object');
      should.not.exist(verifiableCredential.credentialStatus);
      should.exist(verifiableCredential.proof);
      verifiableCredential.proof.should.be.an('object');
    });
    it('issues a valid credential w/oauth2 w/targeted scope', async () => {
      const credential = klona(mockCredential);
      let error;
      let result;
      try {
        const configId = oauth2IssuerConfig.id;
        const url = `${configId}/credentials/issue`;
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId, action: 'write', target: '/credentials/issue'});
        result = await httpClient.post(url, {
          agent,
          headers: {authorization: `Bearer ${accessToken}`},
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      assertNoError(error);
      should.exist(result.data);
      should.exist(result.data.verifiableCredential);
      const {verifiableCredential} = result.data;
      verifiableCredential.should.be.an('object');
      should.exist(verifiableCredential['@context']);
      should.exist(verifiableCredential.id);
      should.exist(verifiableCredential.type);
      should.exist(verifiableCredential.issuer);
      should.exist(verifiableCredential.issuanceDate);
      should.exist(verifiableCredential.credentialSubject);
      verifiableCredential.credentialSubject.should.be.an('object');
      should.not.exist(verifiableCredential.credentialStatus);
      should.exist(verifiableCredential.proof);
      verifiableCredential.proof.should.be.an('object');
    });
    it('fails to issue a valid credential w/bad action scope', async () => {
      const credential = klona(mockCredential);
      let error;
      let result;
      try {
        const configId = oauth2IssuerConfig.id;
        const url = `${configId}/credentials/issue`;
        const accessToken = await helpers.getOAuth2AccessToken(
          // wrong action: `read`
          {configId, action: 'read', target: '/credentials/issue'});
        result = await httpClient.post(url, {
          agent,
          headers: {authorization: `Bearer ${accessToken}`},
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      should.not.exist(result);
      error.status.should.equal(403);
      error.data.type.should.equal('NotAllowedError');
      should.exist(error.data.cause);
      should.exist(error.data.cause.details);
      should.exist(error.data.cause.details.code);
      error.data.cause.details.code.should.equal(
        'ERR_JWT_CLAIM_VALIDATION_FAILED');
      should.exist(error.data.cause.details.claim);
      error.data.cause.details.claim.should.equal('scope');
    });
    it('fails to issue a valid credential w/bad path scope', async () => {
      const credential = klona(mockCredential);
      let error;
      let result;
      try {
        const configId = oauth2IssuerConfig.id;
        const url = `${configId}/credentials/issue`;
        const accessToken = await helpers.getOAuth2AccessToken(
          // wrong path: `/foo`
          {configId, action: 'write', target: '/foo'});
        result = await httpClient.post(url, {
          agent,
          headers: {authorization: `Bearer ${accessToken}`},
          json: {credential}
        });
      } catch(e) {
        error = e;
      }
      should.exist(error);
      should.not.exist(result);
      error.status.should.equal(403);
      error.data.type.should.equal('NotAllowedError');
      should.exist(error.data.cause);
      should.exist(error.data.cause.details);
      should.exist(error.data.cause.details.code);
      error.data.cause.details.code.should.equal(
        'ERR_JWT_CLAIM_VALIDATION_FAILED');
      should.exist(error.data.cause.details.claim);
      error.data.cause.details.claim.should.equal('scope');
    });
  });
});
