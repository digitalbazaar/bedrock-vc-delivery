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

describe('issue APIs', () => {
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
