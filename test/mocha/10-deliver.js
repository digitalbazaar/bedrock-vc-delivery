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
import {OIDC4VCIClient} from './OIDC4VCIClient.js';

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
  it.only('pre-authorized code', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OIDC4VCI issuance initiation URL
    through a CHAPI OIDC4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const issuanceUrl = 'openid-initiate-issuance://?' +
        `issuer=${encodeURIComponent(baseUrl)}` +
        '&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard' +
        '&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA' +
        '&user_pin_required=true';
    const chapiRequest = {OIDC4VCI: issuanceUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    console.log('raw parsed URL', new URL(parsedChapiRequest.OIDC4VCI));
    const initiateIssuanceInfo = OIDC4VCIClient.parseInitiateIssuanceUrl(
      {url: parsedChapiRequest.OIDC4VCI});
    console.log('parsed initiate issuance info', initiateIssuanceInfo);

    // FIXME: get user pin if required
    const userPin = '493536';

    // FIXME: wallet gets access token
    const {issuer, preAuthorizedCode} = initiateIssuanceInfo;
    const client = await OIDC4VCIClient.fromPreAuthorizedCode({
      issuer, preAuthorizedCode, userPin, agent
    });

    /*console.log('generating JWT');
    const signer = {
      algorithm: 'EdDSA', id: 'did:key:1234#5678',
      async sign(data) {
        return new Uint8Array(64);
      }
    };
    const nonce = '1234';
    const iss = 'did:key:1234';
    const aud = 'https://issuer.example';
    const jwt = await OIDC4VCIClient.generateDIDProofJWT(
      {signer, nonce, iss, aud});
    console.log('jwt', jwt);*/

    // FIXME: wallet receives credential
    //const result = await client.requestDelivery();
    // FIXME: assert on result
  });

  it('wallet-initiated', async () => {
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
    const url = '';

    // FIXME: implement OIDC4VCIClient.fromAuthorizationCode()
    const client = await OIDC4VCIClient.fromAuthorizationCode({url, agent});

    // FIXME: request delivery
    const result = await client.requestDelivery();
    // FIXME: assert on result
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
