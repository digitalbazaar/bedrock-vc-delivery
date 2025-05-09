/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const {
  credentialTemplate, credentialRequestTemplate,
  genericCredentialRequestTemplate, genericCredentialTemplate,
  prcCredentialTemplate
} = mockData;

describe('exchange w/ VC-API delivery', () => {
  let capabilityAgent;
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
      template: credentialTemplate
    }];
    const workflowConfig = await helpers.createWorkflowConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

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

    const chapiRequest = {
      VerifiablePresentation: {
        interact: {
          service: [{
            type: 'VerifiableCredentialApiExchangeService',
            serviceEndpoint: exchangeId
          }]
        }
      }
    };
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));

    // post empty body and get VP w/VCs in response
    const {
      VerifiablePresentation: {
        interact: {
          service: [{serviceEndpoint: url}]
        }
      }
    } = parsedChapiRequest;
    const response = await httpClient.post(url, {agent, json: {}});
    const {verifiablePresentation: vp} = response.data;
    // ensure credential subject ID matches static DID
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);
  });

  it('should fail when reusing a completed exchange', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

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

    // exchange state should be pending
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('pending');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }

    // exchange state should be pending using oauth2 access
    {
      let err;
      try {
        const workflowId = exchangeId.slice(
          0, exchangeId.lastIndexOf('/exchanges/'));
        const accessToken = await helpers.getOAuth2AccessToken(
          {configId: workflowId, action: 'read', target: '/'});
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, accessToken});
        should.exist(exchange?.state);
        exchange.state.should.equal('pending');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }

    const chapiRequest = {
      VerifiablePresentation: {
        interact: {
          service: [{
            type: 'VerifiableCredentialApiExchangeService',
            serviceEndpoint: exchangeId
          }]
        }
      }
    };
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));

    // post empty body and get VP w/VCs in response
    const {
      VerifiablePresentation: {
        interact: {
          service: [{serviceEndpoint: url}]
        }
      }
    } = parsedChapiRequest;
    const response = await httpClient.post(url, {agent, json: {}});
    const {verifiablePresentation: vp} = response.data;
    // ensure credential subject ID matches static DID
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);

    // now try to reuse the exchange
    let err;
    try {
      await httpClient.post(url, {agent, json: {}});
    } catch(error) {
      err = error;
    }
    should.exist(err);
    should.equal(err?.data?.name, 'DuplicateError');

    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        // error should be set
        should.exist(exchange.lastError);
        exchange.lastError.name.should.equal('DuplicateError');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }

    // getting exchange state w/o auth should fail
    // FIXME: make this its own test
    {
      let err;
      try {
        await httpClient.get(exchangeId, {agent});
      } catch(error) {
        err = error;
      }
      should.exist(err);
      should.exist(err.data?.name);
      err.data.name.should.equal('NotAllowedError');
    }
  });

  it('should fail when an exchange expires', async function() {
    this.timeout(10000);

    let now = new Date();
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
      workflowRootZcap,
      // TTL of one second
      ttl: 1
    });

    // exchange state should be pending and not yet expired
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('pending');
        should.exist(exchange.expires);
        exchange.expires.should.be.a('string');
        const expires = new Date(exchange.expires);
        const isValidDate = !isNaN(expires);
        isValidDate.should.equal(true);
        expires.should.be.greaterThan(now);

        // wait for exchange to expire
        now = new Date();
        await new Promise(
          r => setTimeout(r, expires.getTime() - now.getTime() + 1));
      } catch(error) {
        err = error;
      }
      should.not.exist(err, err?.message);
    }

    // getting exchange state should result in 404
    {
      let err;
      try {
        await helpers.getExchange({id: exchangeId, capabilityAgent});
      } catch(error) {
        err = error;
      }
      should.exist(err);
      should.exist(err.data?.name);
      err.data.name.should.equal('NotFoundError');
    }
  });
});

describe('exchange w/ VC-API delivery using credential request ' +
  'template', () => {
  let capabilityAgent;
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
      template: credentialRequestTemplate
    }];
    const workflowConfig = await helpers.createWorkflowConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

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

    const chapiRequest = {
      VerifiablePresentation: {
        interact: {
          service: [{
            type: 'VerifiableCredentialApiExchangeService',
            serviceEndpoint: exchangeId
          }]
        }
      }
    };
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));

    // post empty body and get VP w/VCs in response
    const {
      VerifiablePresentation: {
        interact: {
          service: [{serviceEndpoint: url}]
        }
      }
    } = parsedChapiRequest;
    const response = await httpClient.post(url, {agent, json: {}});
    const {verifiablePresentation: vp} = response.data;
    // ensure credential subject ID matches static DID
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID is NOT present
    should.not.exist(vc.id);
  });
});

describe('exchange w/ VC-API delivery using prc template', () => {
  let capabilityAgent;
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
      template: prcCredentialTemplate
    }];
    const workflowConfig = await helpers.createWorkflowConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.prcCredentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });
    const chapiRequest = {
      VerifiablePresentation: {
        interact: {
          service: [{
            type: 'VerifiableCredentialApiExchangeService',
            serviceEndpoint: exchangeId
          }]
        }
      }
    };
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));

    // post empty body and get VP w/VCs in response
    const {
      VerifiablePresentation: {
        interact: {
          service: [{serviceEndpoint: url}]
        }
      }
    } = parsedChapiRequest;
    let response;
    let err;
    try {
      response = await httpClient.post(url, {agent, json: {}});
    } catch(e) {
      err = e;
    }
    should.exist(response);
    should.not.exist(err);
    const {verifiablePresentation: vp} = response.data;
    // ensure credential subject ID matches static DID
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal('did:example:b34ca6cd37bbf23');
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);
  });
});

describe('exchange w/ VC-API delivery using generic credential request ' +
  'template', () => {
  let capabilityAgent;
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
      template: genericCredentialRequestTemplate
    }];
    const workflowConfig = await helpers.createWorkflowConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

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
      workflowRootZcap,
      variables: {
        unusedVariable: {
          'var.with.illegal.mongodb.key1': true,
          var$with$illegal$mongodb$key2: 'stuff',
          'var%with%illegal%mongodb%key3': {}
        },
        credentialId,
        credentialRequest: `{
          'options': {
            'credentialId': $credentialId
          },
          'credential': {
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://www.w3.org/2018/credentials/examples/v1'
            ],
            'type': [
              'VerifiableCredential',
              'UniversityDegreeCredential'
            ],
            'issuanceDate': $issuanceDate,
            'credentialSubject': {
              'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
              'degree': {
                'type': 'BachelorDegree',
                'name': 'Bachelor of Science and Arts'
              }
            }
          }
        }`
      }
    });
    const chapiRequest = {
      VerifiablePresentation: {
        interact: {
          service: [{
            type: 'VerifiableCredentialApiExchangeService',
            serviceEndpoint: exchangeId
          }]
        }
      }
    };
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));

    // post empty body and get VP w/VCs in response
    const {
      VerifiablePresentation: {
        interact: {
          service: [{serviceEndpoint: url}]
        }
      }
    } = parsedChapiRequest;
    let response;
    let err;
    try {
      response = await httpClient.post(url, {agent, json: {}});
    } catch(e) {
      err = e;
    }
    should.exist(response);
    should.not.exist(err);
    const {verifiablePresentation: vp} = response.data;
    // ensure credential subject ID matches static DID
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID is NOT present
    should.not.exist(vc.id);
  });
});

describe('exchange w/ VC-API delivery using generic template', () => {
  let capabilityAgent;
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
      template: genericCredentialTemplate
    }];
    const workflowConfig = await helpers.createWorkflowConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

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
      workflowRootZcap,
      variables: {
        credentialId,
        vc: `{
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://www.w3.org/2018/credentials/examples/v1'
          ],
          'id': $credentialId,
          'type': [
            'VerifiableCredential',
            'UniversityDegreeCredential'
          ],
          'issuanceDate': $issuanceDate,
          'credentialSubject': {
            'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
            'degree': {
              'type': 'BachelorDegree',
              'name': 'Bachelor of Science and Arts'
            }
          }
        }`
      }
    });
    const chapiRequest = {
      VerifiablePresentation: {
        interact: {
          service: [{
            type: 'VerifiableCredentialApiExchangeService',
            serviceEndpoint: exchangeId
          }]
        }
      }
    };
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));

    // post empty body and get VP w/VCs in response
    const {
      VerifiablePresentation: {
        interact: {
          service: [{serviceEndpoint: url}]
        }
      }
    } = parsedChapiRequest;
    let response;
    let err;
    try {
      response = await httpClient.post(url, {agent, json: {}});
    } catch(e) {
      err = e;
    }
    should.exist(response);
    should.not.exist(err);
    const {verifiablePresentation: vp} = response.data;
    // ensure credential subject ID matches static DID
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);
  });
});
