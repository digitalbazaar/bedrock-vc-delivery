/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {getCredentialOffer, OID4Client} from '@digitalbazaar/oid4-client';
import {agent} from '@bedrock/https-agent';
import {mockData} from './mock.data.js';

const {credentialTemplateV2} = mockData;

describe.only('exchange w/OID4VCI 1.0+', () => {
  let capabilityAgent;
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies({
      issuerOptions: {
        issueOptions: {
          cryptosuites: [{
            name: 'ecdsa-rdfc-2019',
            algorithm: 'P-256'
          }]
        }
      }
    });
    const {
      workflowIssueZcap,
      workflowCredentialStatusZcap,
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance
    const zcaps = {
      issue: workflowIssueZcap,
      credentialStatus: workflowCredentialStatusZcap,
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: credentialTemplateV2.replace('subjectName', 'subjectName1')
    }, {
      type: 'jsonata',
      template: credentialTemplateV2.replace('subjectName', 'subjectName2')
    }];
    // FIXME: add variable for including credential config ID in
    // issue request
    const steps = {
      issue: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "issueRequests": [{
              "credentialTemplateIndex": 0,
              "oid4vci": issueRequest1Oid4vci
            }, {
              "credentialTemplateIndex": 1,
              "oid4vci": issueRequest2Oid4vci
            }]
          }`
        }
      }
    };
    const configOptions = {
      credentialTemplates,
      steps,
      initialStep: 'issue',
      issuerInstances: [{
        oid4vci: {
          supportedCredentialConfigurations: {
            myCredentialConfigId_1: {
              format: 'ldp_vc',
              credential_definition: {
                '@context': ['https://www.w3.org/ns/credentials/v2'],
                type: ['VerifiableCredential']
              }
            }
          }
        },
        supportedMediaTypes: ['application/vc'],
        zcapReferenceIds: {
          issue: 'issue'
        }
      }]
    };
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, configOptions, oauth2: true,
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass w/ auto-generated credential config IDs', async () => {
    // pre-authorized flow, issuer-initiated
    const {offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinitionV2,
      variables: {
        subjectName1: 'Name One',
        subjectName2: 'Name Two'
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      useCredentialOfferUri: true
    });

    // get offer from server
    const offer = await getCredentialOffer({url: offerUrl, agent});
    offer.credential_configuration_ids.should.deep.equal(
      ['VerifiableCredential_ldp_vc']);

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client receives credential(s)
    const result = await client.requestCredentials({agent});
    should.exist(result);
    result.should.include.keys('credential_responses');
    const allCredentials = [];
    for(const r of result.credential_responses) {
      r.should.include.keys(['credentials']);
      for(const element of r.credentials) {
        element.should.include.keys(['credential']);
        allCredentials.push(element.credential);
      }
    }

    const namesFound = new Set();
    for(const credential of allCredentials) {
      // gather names to check below
      should.exist(credential.credentialSubject.name);
      namesFound.add(credential.credentialSubject.name);
    }
    // ensure each name matches
    namesFound.size.should.equal(2);
    namesFound.has('Name One').should.equal(true);
    namesFound.has('Name Two').should.equal(true);

    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: offer.credential_issuer, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
      } catch(error) {
        err = error;
      }
      assertNoError(err);
    }
  });

  it('should pass w/ explicit credential config IDs', async () => {
    // pre-authorized flow, issuer-initiated
    const {offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinitionV2,
      variables: {
        subjectName1: 'Name One',
        subjectName2: 'Name Two',
        issueRequest1Oid4vci: {
          credentialConfigurationId: 'myCredentialConfigId_1'
        },
        issueRequest2Oid4vci: {
          credentialConfigurationId: 'myCredentialConfigId_1'
        }
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      useCredentialOfferUri: true
    });

    // get offer from server
    const offer = await getCredentialOffer({url: offerUrl, agent});
    offer.credential_configuration_ids.should.deep.equal(
      ['myCredentialConfigId_1']);

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client receives credential(s)
    const result = await client.requestCredentials({agent});
    should.exist(result);
    result.should.include.keys('credential_responses');
    const allCredentials = [];
    for(const r of result.credential_responses) {
      r.should.include.keys(['credentials']);
      for(const element of r.credentials) {
        element.should.include.keys(['credential']);
        allCredentials.push(element.credential);
      }
    }

    const namesFound = new Set();
    for(const credential of allCredentials) {
      // gather names to check below
      should.exist(credential.credentialSubject.name);
      namesFound.add(credential.credentialSubject.name);
    }
    // ensure each name matches
    namesFound.size.should.equal(2);
    namesFound.has('Name One').should.equal(true);
    namesFound.has('Name Two').should.equal(true);

    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: offer.credential_issuer, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
      } catch(error) {
        err = error;
      }
      assertNoError(err);
    }
  });
});
