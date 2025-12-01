/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const {
  baseUrl, didAuthnCredentialTemplate, strictDegreePresentationSchema
} = mockData;

describe('exchange w/ VC-API delivery + "issueRequests"', () => {
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

  async function _provisionWorkflow({stepCount}) {
    // provision workflow that will require the provisioned VC above
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
      id: 'urn:credential-template-1',
      type: 'jsonata',
      template: didAuthnCredentialTemplate
    }];
    const jsonSchema = structuredClone(strictDegreePresentationSchema);
    // FIXME: create a function to inject required `issuer` value
    jsonSchema.properties.verifiableCredential.oneOf[0]
      .properties.issuer = {const: verifiableCredential.issuer};
    jsonSchema.properties.verifiableCredential.oneOf[1].items
      .properties.issuer = {const: verifiableCredential.issuer};
    // require semantically-named workflow steps
    let steps;
    if(stepCount === 1) {
      steps = {
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
                    'https://www.w3.org/2018/credentials/v1',
                    'https://www.w3.org/2018/credentials/examples/v1'
                  ],
                  type: 'UniversityDegreeCredential'
                }
              }]
            }],
            domain: baseUrl
          },
          presentationSchema: {
            type: 'JsonSchema',
            jsonSchema
          },
          // issue same VC twice
          issueRequests: [{
            credentialTemplateId: 'urn:credential-template-1'
          }, {
            credentialTemplateId: 'urn:credential-template-1',
            // use different variables
            variables: {
              credentialId: 'urn:different',
              issuanceDate: '2024-01-01T00:00:00Z',
              results: {
                didAuthn: {
                  did: 'did:example:1'
                }
              }
            }
          }]
        }
      };
    } else {
      steps = {
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
                    'https://www.w3.org/2018/credentials/v1',
                    'https://www.w3.org/2018/credentials/examples/v1'
                  ],
                  type: 'UniversityDegreeCredential'
                }
              }]
            }],
            domain: baseUrl
          },
          presentationSchema: {
            type: 'JsonSchema',
            jsonSchema
          },
          nextStep: 'issue'
        },
        issue: {
          // issue same VC twice
          issueRequests: [{
            credentialTemplateId: 'urn:credential-template-1'
          }, {
            credentialTemplateId: 'urn:credential-template-1',
            // use different variables
            variables: {
              credentialId: 'urn:different',
              issuanceDate: '2024-01-01T00:00:00Z',
              results: {
                didAuthn: {
                  did: 'did:example:1'
                }
              }
            }
          }]
        }
      };
    }
    // set initial step
    const initialStep = 'didAuthn';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, credentialTemplates, steps, initialStep,
      oauth2: true
    });
    const workflowId = workflowConfig.id;
    const workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
    return {workflowId, workflowRootZcap};
  }

  it('should pass when sending VP in single call w/one step', async () => {
    const {workflowId, workflowRootZcap} = await _provisionWorkflow({
      stepCount: 1
    });

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
      did, signer, verifiableCredential
    });

    // post VP to get VP in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    should.exist(response?.data?.verifiablePresentation);
    // ensure DID in VC matches `did`
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    should.exist(vp?.verifiableCredential?.[1]?.credentialSubject?.id);
    const {verifiableCredential: [vc1, vc2]} = vp;
    vc1.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(vc1.id);
    vc1.id.should.equal(credentialId);

    // check second VC
    vc2.credentialSubject.id.should.equal('did:example:1');
    // ensure VC ID matches expected value
    should.exist(vc2.id);
    vc2.id.should.equal('urn:different');

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

  it('should pass when sending VP in single call w/two steps', async () => {
    const {workflowId, workflowRootZcap} = await _provisionWorkflow({
      stepCount: 2
    });

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
      did, signer, verifiableCredential
    });

    // post VP to get VP in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    should.exist(response?.data?.verifiablePresentation);
    // ensure DID in VC matches `did`
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    should.exist(vp?.verifiableCredential?.[1]?.credentialSubject?.id);
    const {verifiableCredential: [vc1, vc2]} = vp;
    vc1.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(vc1.id);
    vc1.id.should.equal(credentialId);

    // check second VC
    vc2.credentialSubject.id.should.equal('did:example:1');
    // ensure VC ID matches expected value
    should.exist(vc2.id);
    vc2.id.should.equal('urn:different');

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
