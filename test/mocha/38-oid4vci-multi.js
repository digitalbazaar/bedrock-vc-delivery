/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {
  getCredentialOffer,
  OID4Client,
  parseCredentialOfferUrl
} from '@digitalbazaar/oid4-client';
import {agent} from '@bedrock/https-agent';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const {credentialTemplate} = mockData;

describe('exchange multiple VCs w/OID4VCI delivery', () => {
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
      template: credentialTemplate.replace('credentialId', 'credentialId1')
    }, {
      type: 'jsonata',
      template: credentialTemplate.replace('credentialId', 'credentialId2')
    }];
    const workflowConfig = await helpers.createWorkflowConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass w/ pre-authorized code flow', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OID4VCI issuance initiation URL
    through a CHAPI OID4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId1 = `urn:uuid:${uuid()}`;
    const credentialId2 = `urn:uuid:${uuid()}`;
    const {openIdUrl: offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      variables: {
        credentialId1,
        credentialId2
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });
    const chapiRequest = {OID4VCI: offerUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const offer = parseCredentialOfferUrl({url: parsedChapiRequest.OID4VCI});

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client receives credential
    const result = await client.requestCredential({agent});
    should.exist(result);
    result.should.include.keys(['format', 'credentials']);
    result.format.should.equal('ldp_vc');

    const credentialIdsFound = new Set();
    for(const credential of result.credentials) {
      // ensure each credential subject ID matches static DID
      should.exist(credential.credentialSubject?.id);
      credential.credentialSubject.id.should.equal(
        'did:example:ebfeb1f712ebc6f1c276e12ec21');
      // gather VC IDs to check below
      should.exist(credential.id);
      credentialIdsFound.add(credential.id);
    }
    // ensure each VC ID matches
    credentialIdsFound.size.should.equal(2);
    credentialIdsFound.has(credentialId1).should.equal(true);
    credentialIdsFound.has(credentialId2).should.equal(true);

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
      should.not.exist(err);
    }
  });

  it('should pass w/ credentials as ID strings in offer', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OID4VCI issuance initiation URL
    through a CHAPI OID4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId1 = `urn:uuid:${uuid()}`;
    const credentialId2 = `urn:uuid:${uuid()}`;
    const {openIdUrl: offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      variables: {
        credentialId1,
        credentialId2
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      useCredentialIds: true
    });
    const chapiRequest = {OID4VCI: offerUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const offer = parseCredentialOfferUrl({url: parsedChapiRequest.OID4VCI});

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client receives credential
    const result = await client.requestCredential({agent});
    should.exist(result);
    result.should.include.keys(['format', 'credentials']);
    result.format.should.equal('ldp_vc');

    const credentialIdsFound = new Set();
    for(const credential of result.credentials) {
      // ensure each credential subject ID matches static DID
      should.exist(credential.credentialSubject?.id);
      credential.credentialSubject.id.should.equal(
        'did:example:ebfeb1f712ebc6f1c276e12ec21');
      // gather VC IDs to check below
      should.exist(credential.id);
      credentialIdsFound.add(credential.id);
    }
    // ensure each VC ID matches
    credentialIdsFound.size.should.equal(2);
    credentialIdsFound.has(credentialId1).should.equal(true);
    credentialIdsFound.has(credentialId2).should.equal(true);

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
      should.not.exist(err);
    }
  });

  it('should pass w/ credential configuration IDs', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OID4VCI issuance initiation URL
    through a CHAPI OID4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId1 = `urn:uuid:${uuid()}`;
    const credentialId2 = `urn:uuid:${uuid()}`;
    const {openIdUrl: offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      variables: {
        credentialId1,
        credentialId2
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      useCredentialConfigurationIds: true
    });
    const chapiRequest = {OID4VCI: offerUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const offer = parseCredentialOfferUrl({url: parsedChapiRequest.OID4VCI});

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client receives credential
    const result = await client.requestCredential({agent});
    should.exist(result);
    result.should.include.keys(['format', 'credentials']);
    result.format.should.equal('ldp_vc');

    const credentialIdsFound = new Set();
    for(const credential of result.credentials) {
      // ensure each credential subject ID matches static DID
      should.exist(credential.credentialSubject?.id);
      credential.credentialSubject.id.should.equal(
        'did:example:ebfeb1f712ebc6f1c276e12ec21');
      // gather VC IDs to check below
      should.exist(credential.id);
      credentialIdsFound.add(credential.id);
    }
    // ensure each VC ID matches
    credentialIdsFound.size.should.equal(2);
    credentialIdsFound.has(credentialId1).should.equal(true);
    credentialIdsFound.has(credentialId2).should.equal(true);

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
      should.not.exist(err);
    }
  });

  it('should pass w/ "credential_offer_uri"', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OID4VCI issuance initiation URL
    through a CHAPI OID4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId1 = `urn:uuid:${uuid()}`;
    const credentialId2 = `urn:uuid:${uuid()}`;
    const {openIdUrl: offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      variables: {
        credentialId1,
        credentialId2
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      useCredentialOfferUri: true
    });
    const chapiRequest = {OID4VCI: offerUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const offer = await getCredentialOffer({
      url: parsedChapiRequest.OID4VCI, agent
    });

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client receives credential
    const result = await client.requestCredential({agent});
    should.exist(result);
    result.should.include.keys(['format', 'credentials']);
    result.format.should.equal('ldp_vc');

    const credentialIdsFound = new Set();
    for(const credential of result.credentials) {
      // ensure each credential subject ID matches static DID
      should.exist(credential.credentialSubject?.id);
      credential.credentialSubject.id.should.equal(
        'did:example:ebfeb1f712ebc6f1c276e12ec21');
      // gather VC IDs to check below
      should.exist(credential.id);
      credentialIdsFound.add(credential.id);
    }
    // ensure each VC ID matches
    credentialIdsFound.size.should.equal(2);
    credentialIdsFound.has(credentialId1).should.equal(true);
    credentialIdsFound.has(credentialId2).should.equal(true);

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
      should.not.exist(err);
    }
  });
});
