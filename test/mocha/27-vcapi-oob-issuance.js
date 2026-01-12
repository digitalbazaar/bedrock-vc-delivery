/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const {
  baseUrl, didAuthnCredentialTemplate
} = mockData;

describe('exchange w/ VC-API delivery of out-of-band issued VCs', () => {
  let capabilityAgent;

  // provision a VC to use in the workflow below
  let verifiableCredential;
  let did;
  let signer;
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
    const steps = {
      finish: {
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
    const initialStep = 'finish';
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

  // provision workflow that will include only the provisioned VC above
  let workflowId1;
  let workflowRootZcap1;
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
    const steps = {
      finish: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "verifiableCredentials": [issuedOutOfBand]
          }`
        }
      }
    };
    const initialStep = 'finish';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, steps, initialStep,
      oauth2: true
    });
    workflowId1 = workflowConfig.id;
    workflowRootZcap1 = `urn:zcap:root:${encodeURIComponent(workflowId1)}`;
  });

  // provision workflow that will include the provisioned VC above and another
  // VC that is issued during the workflow in a single step
  let workflowId2;
  let workflowRootZcap2;
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
    const steps = {
      didAuthn: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "createChallenge": true,
            "verifiablePresentationRequest": verifiablePresentationRequest,
            "issueRequests": [{
              "credentialTemplateIndex": 0
            }],
            "verifiableCredentials": [issuedOutOfBand]
          }`
        }
      }
    };
    const initialStep = 'didAuthn';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, credentialTemplates, steps, initialStep,
      oauth2: true
    });
    workflowId2 = workflowConfig.id;
    workflowRootZcap2 = `urn:zcap:root:${encodeURIComponent(workflowId2)}`;
  });

  // provision workflow that will include the provisioned VC above and another
  // VC that is issued during the workflow in two steps
  let workflowId3;
  let workflowRootZcap3;
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
    const steps = {
      didAuthn: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "createChallenge": true,
            "verifiablePresentationRequest": verifiablePresentationRequest,
            "nextStep": "finish"
          }`
        }
      },
      finish: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "issueRequests": [{
              "credentialTemplateIndex": 0
            }],
            "verifiableCredentials": [issuedOutOfBand]
          }`
        }
      }
    };
    const initialStep = 'didAuthn';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, credentialTemplates, steps, initialStep,
      oauth2: true
    });
    workflowId3 = workflowConfig.id;
    workflowRootZcap3 = `urn:zcap:root:${encodeURIComponent(workflowId3)}`;
  });

  it('should pass when receiving only the out-of-band VC', async () => {
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId: workflowId1,
      workflowRootZcap: workflowRootZcap1,
      variables: {
        issuedOutOfBand: verifiableCredential
      }
    });

    // post empty JSON to get VP in response
    const response = await httpClient.post(exchangeId, {agent, json: {}});
    should.exist(response?.data?.verifiablePresentation);
    // ensure first VC matches variable
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]);
    vp.verifiableCredential[0].should.deep.equal(verifiableCredential);

    // exchange should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
      } catch(error) {
        err = error;
      }
      assertNoError(err);
    }
  });

  it('should pass w/ out-of-band + another VC in one step', async () => {
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId: workflowId2,
      workflowRootZcap: workflowRootZcap2,
      variables: {
        credentialId,
        issuedOutOfBand: verifiableCredential,
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
                  'https://www.w3.org/2018/credentials/v1',
                  'https://www.w3.org/2018/credentials/examples/v1'
                ],
                type: 'UniversityDegreeCredential'
              }
            }]
          }],
          domain: baseUrl
        }
      }
    });

    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential
    });

    // post VP to get VP in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    should.exist(response?.data?.verifiablePresentation);
    // ensure first VC matches variable
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]);
    vp.verifiableCredential[0].should.deep.equal(verifiableCredential);
    // check second VC...
    // ensure DID in VC matches `did`
    const {verifiableCredential: [, vc]} = vp;
    vc.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    vc.id.should.equal(credentialId);
    // ensure second VC does NOT equal first one
    vp.verifiableCredential[0].should.not.deep.equal(
      vp.verifiableCredential[1]);

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
      assertNoError(err);
    }
  });

  it('should pass w/ out-of-band + another VC in two steps', async () => {
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId: workflowId2,
      workflowRootZcap: workflowRootZcap2,
      variables: {
        credentialId,
        issuedOutOfBand: verifiableCredential,
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
                  'https://www.w3.org/2018/credentials/v1',
                  'https://www.w3.org/2018/credentials/examples/v1'
                ],
                type: 'UniversityDegreeCredential'
              }
            }]
          }],
          domain: baseUrl
        }
      }
    });

    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential
    });

    // post VP to get VP in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    should.exist(response?.data?.verifiablePresentation);
    // ensure first VC matches variable
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]);
    vp.verifiableCredential[0].should.deep.equal(verifiableCredential);
    // check second VC...
    // ensure DID in VC matches `did`
    const {verifiableCredential: [, vc]} = vp;
    vc.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    vc.id.should.equal(credentialId);
    // ensure second VC does NOT equal first one
    vp.verifiableCredential[0].should.not.deep.equal(
      vp.verifiableCredential[1]);

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
      assertNoError(err);
    }
  });
});
