/*!
 * Copyright (c) 2024-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {util} from '@digitalbazaar/vpqr';
import {v4 as uuid} from 'uuid';

const {
  baseUrl, didAuthnCredentialTemplate
} = mockData;

describe('exchange w/ VC-API delivery + ' +
  'VC request w/unprotected VP', () => {
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

  // provision workflow that will require the provisioned VC above with
  // the option to not require a protected VP
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    const zcaps = {
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    // require semantically-named workflow steps
    const steps = {
      initial: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "allowUnprotectedPresentation":
              $exists(allowUnprotectedPresentation) ?
                allowUnprotectedPresentation : false,
            "createChallenge": true,
            "verifiablePresentationRequest": verifiablePresentationRequest
          }`
        }
      }
    };
    // set initial step
    const initialStep = 'initial';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, steps, initialStep,
      oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass with protected presentation', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        allowUnprotectedPresentation: true,
        verifiablePresentationRequest: {
          query: {
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
          },
          domain: baseUrl
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });

    // post to exchange URL to get expected VPR
    let response = await httpClient.post(
      exchangeId, {agent, json: {}});
    should.exist(response?.data?.verifiablePresentationRequest);
    const {data: {verifiablePresentationRequest: vpr}} = response;
    const expectedVpr = {
      query: {
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
      },
      domain: baseUrl
    };
    expectedVpr.query.should.deep.equal(vpr.query);
    expectedVpr.domain.should.deep.equal(vpr.domain);
    should.exist(vpr.challenge);

    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential
    });

    response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    // should be no VP nor VPR in the response, indicating the end of the
    // exchange (and nothing was issued, just presented)
    should.not.exist(response?.data?.verifiablePresentation);
    should.not.exist(response?.data?.verifiablePresentationRequest);

    // exchange should be complete and contain the submitted VPR
    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.initial);
        should.exist(
          exchange?.variables?.results?.initial?.verifiablePresentation);
        exchange?.variables?.results?.initial.did.should.equal(did);
        exchange.variables.results.initial.verifiablePresentation
          .should.deep.equal(verifiablePresentation);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });

  it('should fail with unprotected presentation', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        verifiablePresentationRequest: {
          query: {
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
          },
          domain: baseUrl
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });

    // post to exchange URL to get expected VPR
    let response = await httpClient.post(
      exchangeId, {agent, json: {}});
    should.exist(response?.data?.verifiablePresentationRequest);
    const {data: {verifiablePresentationRequest: vpr}} = response;
    const expectedVpr = {
      query: {
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
      },
      domain: baseUrl
    };
    expectedVpr.query.should.deep.equal(vpr.query);
    expectedVpr.domain.should.deep.equal(vpr.domain);
    should.exist(vpr.challenge);

    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential
    });
    // remove `proof` from VP
    delete verifiablePresentation.proof;

    let err;
    try {
      response = await httpClient.post(
        exchangeId, {agent, json: {verifiablePresentation}});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.data.name.should.equal('DataError');
    err.data.details.verified.should.equal(false);
    should.exist(err.data.details.errors);
  });

  it('should pass when unprotected presentation is allowed', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        allowUnprotectedPresentation: true,
        verifiablePresentationRequest: {
          query: {
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
          },
          domain: baseUrl
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });

    // post to exchange URL to get expected VPR
    let response = await httpClient.post(
      exchangeId, {agent, json: {}});
    should.exist(response?.data?.verifiablePresentationRequest);
    const {data: {verifiablePresentationRequest: vpr}} = response;
    const expectedVpr = {
      query: {
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
      },
      domain: baseUrl
    };
    expectedVpr.query.should.deep.equal(vpr.query);
    expectedVpr.domain.should.deep.equal(vpr.domain);
    should.exist(vpr.challenge);

    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential
    });
    // remove `proof` from VP
    delete verifiablePresentation.proof;

    let err;
    try {
      response = await httpClient.post(
        exchangeId, {agent, json: {verifiablePresentation}});
    } catch(e) {
      err = e;
    }
    should.not.exist(err);

    // should be no VP nor VPR in the response, indicating the end of the
    // exchange (and nothing was issued, just presented)
    should.not.exist(response?.data?.verifiablePresentation);
    should.not.exist(response?.data?.verifiablePresentationRequest);

    // exchange should be complete and contain the submitted VPR
    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.initial);
        should.exist(
          exchange?.variables?.results?.initial?.verifiablePresentation);
        should.not.exist(exchange?.variables?.results?.initial.did);
        exchange.variables.results.initial.verifiablePresentation
          .should.deep.equal(verifiablePresentation);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });

  it('should pass w/enveloped VC in unprotected VP', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        allowUnprotectedPresentation: true,
        verifiablePresentationRequest: {
          query: {
            type: 'QueryByExample',
            credentialQuery: [{
              reason: 'We require an enveloped verifiable credential to pass',
              example: {
                '@context': [
                  'https://www.w3.org/2018/credentials/v2'
                ],
                type: 'EnvelopedVerifiableCredential'
              }
            }]
          },
          domain: baseUrl
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });

    // post to exchange URL to get expected VPR
    let response = await httpClient.post(
      exchangeId, {agent, json: {}});
    should.exist(response?.data?.verifiablePresentationRequest);
    const {data: {verifiablePresentationRequest: vpr}} = response;
    const expectedVpr = {
      query: {
        type: 'QueryByExample',
        credentialQuery: [{
          reason: 'We require an enveloped verifiable credential to pass',
          example: {
            '@context': [
              'https://www.w3.org/2018/credentials/v2'
            ],
            type: 'EnvelopedVerifiableCredential'
          }
        }]
      },
      domain: baseUrl
    };
    expectedVpr.query.should.deep.equal(vpr.query);
    expectedVpr.domain.should.deep.equal(vpr.domain);
    should.exist(vpr.challenge);

    const {payload} = await util.toQrCode({
      header: 'VC1-',
      jsonldDocument: verifiableCredential,
      documentLoader: helpers.documentLoader,
      qrMultibaseEncoding: 'R',
      diagnose: null,
      registryEntryId: 1
    });
    const envelopedVerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'data:application/vcb;barcode-format=qr_code;base64,' +
        Buffer.from(payload, 'utf8').toString('base64'),
      type: 'EnvelopedVerifiableCredential'
    };
    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential: envelopedVerifiableCredential
    });
    // remove `proof` from VP
    delete verifiablePresentation.proof;

    let err;
    try {
      response = await httpClient.post(
        exchangeId, {agent, json: {verifiablePresentation}});
    } catch(e) {
      err = e;
    }
    should.not.exist(err);

    // should be no VP nor VPR in the response, indicating the end of the
    // exchange (and nothing was issued, just presented)
    should.not.exist(response?.data?.verifiablePresentation);
    should.not.exist(response?.data?.verifiablePresentationRequest);

    // exchange should be complete and contain the submitted VPR
    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.initial);
        should.exist(
          exchange?.variables?.results?.initial?.verifiablePresentation);
        should.not.exist(exchange?.variables?.results?.initial.did);
        exchange.variables.results.initial.verifiablePresentation
          .should.deep.equal({
            ...verifiablePresentation,
            verifiableCredential: [verifiableCredential]
          });
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });

  it('should fail when VM not found', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        allowUnprotectedPresentation: true,
        verifiablePresentationRequest: {
          query: {
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
          },
          domain: baseUrl
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });

    // post to exchange URL to get expected VPR
    {
      const response = await httpClient.post(
        exchangeId, {agent, json: {}});
      should.exist(response?.data?.verifiablePresentationRequest);
      const {data: {verifiablePresentationRequest: vpr}} = response;
      const expectedVpr = {
        query: {
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
        },
        domain: baseUrl
      };
      expectedVpr.query.should.deep.equal(vpr.query);
      expectedVpr.domain.should.deep.equal(vpr.domain);
      should.exist(vpr.challenge);
    }

    const invalidVerifiableCredential = structuredClone(verifiableCredential);
    invalidVerifiableCredential.proof.verificationMethod =
      'did:web:localhost:not-found';

    // generate VP
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer, verifiableCredential: invalidVerifiableCredential
    });
    // remove `proof` from VP
    delete verifiablePresentation.proof;

    // verification should fail because VC's VM is not found
    let err;
    let response;
    try {
      response = await httpClient.post(
        exchangeId, {agent, json: {verifiablePresentation}});
    } catch(e) {
      err = e;
    }
    should.not.exist(response);
    should.exist(err);
    err.status.should.equal(400);
    err.data.name.should.equal('DataError');
    const verifierError = err.data.details.error;
    verifierError.name.should.equal('VerificationError');
    const credentialResults = err.data.details.credentialResults;
    should.exist(credentialResults);
    // ideally a 404 NotFoundError is here, but it could also be
    // a simple "fetch failed" message
    should.exist(credentialResults[0].error?.errors?.[0]);

    // exchange state should be active with last error set
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        // error should be set
        should.exist(exchange.lastError);
        exchange.lastError.name.should.equal('DataError');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });
});
