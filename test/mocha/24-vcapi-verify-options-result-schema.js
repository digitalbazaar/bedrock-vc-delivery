/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import * as vc from '@digitalbazaar/vc';
import {agent} from '@bedrock/https-agent';
import {documentLoader as brDocLoader} from '@bedrock/jsonld-document-loader';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';
import https from 'node:https';
import path from 'node:path';
import fs from 'node:fs';
import express from 'express';
import {fileURLToPath} from 'node:url';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';

import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const VC_V2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';

const {
  baseUrl, didAuthnCredentialTemplate, strictDegreePresentationSchema
} = mockData;

const encodedList100KWith50KthRevoked =
  'uH4sIAAAAAAAAA-3OMQ0AAAgDsElHOh72EJJWQRMAAAAAAIDWXAcAAAAAAIDHFvRitn7UMAAA';
const key = fs.readFileSync(__dirname + '/key.pem');
const cert = fs.readFileSync(__dirname + '/cert.pem');

let slcRevocation;
let unsignedCredentialWithRevokedIndex;
let unsignedCredentialWithUnrevokedIndex;

// load docs from test server (e.g., load SL VCs)
let testServerBaseUrl;
async function _documentLoader(url) {
  if(url.startsWith(testServerBaseUrl)) {
    const response = await httpClient.get(url, {agent});
    return {
      contextUrl: null,
      documentUrl: url,
      document: response.data
    };
  }
  return brDocLoader(url);
}

function _startServer({app}) {
  return new Promise(resolve => {
    const server = https.createServer({key, cert}, app);
    server.listen(() => {
      const {port} = server.address();
      const BASE_URL = `https://localhost:${port}`;
      testServerBaseUrl = BASE_URL;
      console.log(`Test server listening at ${BASE_URL}`);

      // SLC with statusPurpose `revocation`
      slcRevocation = {
        '@context': [
          VC_V2_CONTEXT_URL
        ],
        id: `${BASE_URL}/status/748a7d8e-9111-11ec-a934-10bf48838a41`,
        issuer: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
        validFrom: '2022-01-10T04:24:12.164Z',
        type: ['VerifiableCredential', 'BitstringStatusListCredential'],
        credentialSubject: {
          id: `${BASE_URL}/status/748a7d8e-9111-11ec-a934-10bf48838a41#list`,
          type: 'BitstringStatusList',
          statusPurpose: 'revocation',
          encodedList: encodedList100KWith50KthRevoked
        }
      };

      // unsigned VC with "credentialStatus.statusPurpose" `revocation`
      unsignedCredentialWithRevokedIndex = {
        '@context': [
          VC_V2_CONTEXT_URL,
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
        type: ['VerifiableCredential', 'example:TestCredential'],
        credentialSubject: {
          id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
          'example:test': 'foo'
        },
        credentialStatus: {
          id: `${BASE_URL}/status/748a7d8e-9111-11ec-a934-10bf48838a41#50000`,
          type: 'BitstringStatusListEntry',
          statusPurpose: 'revocation',
          statusListIndex: '50000',
          statusListCredential: slcRevocation.id
        },
        issuer: slcRevocation.issuer,
      };

      // unsigned VC with "credentialStatus.statusPurpose" `revocation`
      unsignedCredentialWithUnrevokedIndex = {
        '@context': [
          VC_V2_CONTEXT_URL,
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: 'urn:uuid:a0418a78-7924-11ea-8a23-10bf48838a41',
        type: ['VerifiableCredential', 'example:TestCredential'],
        credentialSubject: {
          id: 'urn:uuid:4886029a-7925-11ea-9274-10bf48838a41',
          'example:test': 'foo'
        },
        credentialStatus: {
          id: `${BASE_URL}/status/748a7d8e-9111-11ec-a934-10bf48838a41#67342`,
          type: 'BitstringStatusListEntry',
          statusPurpose: 'revocation',
          statusListIndex: '67342',
          statusListCredential: slcRevocation.id
        },
        issuer: slcRevocation.issuer,
      };

      return resolve(server);
    });
  });
}

const app = express();
app.use(express.json());

// mount the test routes
app.get('/status/748a7d8e-9111-11ec-a934-10bf48838a41',
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    // responds with a valid SLC
    res.json(slcRevocation);
  });
let server;
before(async () => {
  server = await _startServer({app});
});
after(async () => {
  server.close();
});

describe('exchange w/ VC-API delivery + DID authn + VC request -STATUS-', () => {
  let capabilityAgent;

  // provision a VC to use in the workflow below
  let verifiableCredential;
  let vcUnrevoked;
  let vcRevoked;
  let did;
  let signer;
  let keyData;
  let keyPair;
  let suite;
  beforeEach(async () => {

    keyData = {
      id: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv#' +
        'z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      controller: 'did:key:z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      type: 'Ed25519VerificationKey2020',
      publicKeyMultibase: 'z6Mktpn6cXks1PBKLMgZH2VaahvCtBMF6K8eCa7HzrnuYLZv',
      privateKeyMultibase: 'zrv2rP9yjtz3YwCas9m6hnoPxmoqZV72xbCEuomXi4wwSS' +
        '4ShekesADYiAMHoxoqfyBDKQowGMvYx9rp6QGJ7Qbk7Y4'
    };
    keyPair = await Ed25519VerificationKey2020.from(keyData);
    suite = new Ed25519Signature2020({key: keyPair});



    const deps = await helpers.provisionDependencies();
    const {
      workflowIssueZcap,
      workflowCredentialStatusZcap,
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    const zcaps = {
      issue: workflowIssueZcap,
      credentialStatus: workflowCredentialStatusZcap,
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: didAuthnCredentialTemplate
    }];
    // require semantically-named workflow steps
    const steps = {
      // DID Authn step
      didAuthn: {
        createChallenge: true,
        verifiablePresentationRequest: {
          query: {
            type: 'DIDAuthentication',
            acceptedMethods: [{method: 'key'}]
          },
          domain: baseUrl
        }
      }
    };
    // set initial step
    const initialStep = 'didAuthn';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, credentialTemplates, steps, initialStep,
      oauth2: true
    });
    const workflowId = workflowConfig.id;
    const workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;

    // use workflow to provision verifiable credential
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });

    // generate VP
    ({did, signer} = await helpers.createDidProofSigner());
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer
    });

    // post VP to get VP w/VC in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    const {verifiablePresentation: vp} = response.data;
    verifiableCredential = vp.verifiableCredential[0];
  });

  // provision workflow that will require the provisioned VC above
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      workflowIssueZcap,
      workflowCredentialStatusZcap,
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    const zcaps = {
      issue: workflowIssueZcap,
      credentialStatus: workflowCredentialStatusZcap,
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: didAuthnCredentialTemplate
    }];

    // require semantically-named workflow steps
    const steps = {
      // DID Authn step, additionally require VC that was issued from
      // workflow 1
      didAuthn: {
        createChallenge: true,
        verifiablePresentationRequest: {
          query: [{
            type: 'DIDAuthentication',
            acceptedMethods: [{method: 'key'}]
          }, {
            type: 'QueryByExample',
            credentialQuery: [{
              reason: 'We require a verifiable credential to pass this test',
              example: {
                '@context': [
                  'https://www.w3.org/ns/credentials/v2'
                ],
              }
            }]
          }],
          domain: baseUrl
        },
        verifyPresentationOptions: {
          checks: {
            credentialStatus: true
          }
        },
        verifyPresentationResultSchema: {
          type: 'JsonSchema',
          jsonSchema
        }
      }
    };
    // set initial step
    const initialStep = 'didAuthn';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, credentialTemplates, steps, initialStep,
      oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;

    slcRevocation = await vc.issue({
      credential: slcRevocation,
      documentLoader: _documentLoader,
      suite
    });
    vcUnrevoked = await vc.issue({
      credential: unsignedCredentialWithUnrevokedIndex,
      documentLoader: _documentLoader,
      suite
    });
    vcRevoked = await vc.issue({
      credential: unsignedCredentialWithRevokedIndex,
      documentLoader: _documentLoader,
      suite
    });
  });

  it.only('should pass when sending VP in single call', async () => {
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });

    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential: vcUnrevoked
    });

    // post VP to get VP in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    should.exist(response?.data?.verifiablePresentation);
    // ensure DID in VC matches `did`
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);

    // exchange should be complete and contain the VP and original VC
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.didAuthn);
        should.exist(
          exchange?.variables?.results?.didAuthn?.verifiablePresentation);
        exchange?.variables?.results?.didAuthn.did.should.equal(did);
        exchange.variables.results.didAuthn.verifiablePresentation
          .should.deep.equal(verifiablePresentation);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });
  it('should fail', async () => {
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });

    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential: vcRevoked
    });
    console.log(JSON.stringify(verifiablePresentation, null, 2));

    // post VP to get VP in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    should.exist(response?.data?.verifiablePresentation);
    // ensure DID in VC matches `did`
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);

    // exchange should be complete and contain the VP and original VC
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.didAuthn);
        should.exist(
          exchange?.variables?.results?.didAuthn?.verifiablePresentation);
        exchange?.variables?.results?.didAuthn.did.should.equal(did);
        exchange.variables.results.didAuthn.verifiablePresentation
          .should.deep.equal(verifiablePresentation);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });

});
