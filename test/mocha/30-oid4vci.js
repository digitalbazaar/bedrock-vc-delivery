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
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const {credentialTemplate} = mockData;

describe('exchange w/OID4VCI delivery', () => {
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

  it('should pass w/ pre-authorized code flow', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OID4VCI issuance initiation URL
    through a CHAPI OID4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    const {openIdUrl: offerUrl} = await helpers.createCredentialOffer({
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
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches static DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);

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
    const credentialId = `urn:uuid:${uuid()}`;
    const {openIdUrl: offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
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
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches static DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);

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
    const credentialId = `urn:uuid:${uuid()}`;
    const {openIdUrl: offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
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
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches static DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);

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
    const credentialId = `urn:uuid:${uuid()}`;
    const {
      exchangeId,
      openIdUrl: offerUrl
    } = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
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

    // confirm offer URL matches the one in `protocols`
    {
      const protocolsUrl = `${exchangeId}/protocols`;
      const response = await httpClient.get(protocolsUrl, {agent});
      should.exist(response);
      should.exist(response.data);
      should.exist(response.data.protocols);
      should.exist(response.data.protocols.vcapi);
      response.data.protocols.vcapi.should.equal(exchangeId);
      should.exist(response.data.protocols.OID4VCI);
      response.data.protocols.OID4VCI.should.equal(offerUrl);
    }

    // confirm 406 when not requesting JSON
    {
      const protocolsUrl = `${exchangeId}/protocols`;
      let response;
      let error;
      try {
        response = await httpClient.get(protocolsUrl, {
          agent,
          headers: {
            accept: 'text/html'
          }
        });
      } catch(e) {
        error = e;
      }
      should.not.exist(response);
      should.exist(error);
      error.status.should.equal(406);
    }

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client receives credential
    const result = await client.requestCredential({agent});
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches static DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);

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

  it('should pass w/ pre-authorized code flow w/ AS key pair', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OID4VCI issuance initiation URL
    through a CHAPI OID4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    // generate authorization server key pair
    const openIdKeyPair = await helpers.generateKeyPair();
    const {openIdUrl: issuanceUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      openIdKeyPair
    });

    const chapiRequest = {OID4VCI: issuanceUrl};
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
    const result = await client.requestCredential({
      credentialDefinition: mockData.credentialDefinition,
      agent
    });
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches static DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);
  });

  it('should pass w/ "types" in credential definition', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OID4VCI issuance initiation URL
    through a CHAPI OID4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    // generate authorization server key pair
    const openIdKeyPair = await helpers.generateKeyPair();
    const {openIdUrl: issuanceUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      openIdKeyPair
    });

    const chapiRequest = {OID4VCI: issuanceUrl};
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

    // send OID4VCI draft 20 credential definition w/"types" which should
    // work with backwards compatibility support
    const credentialDefinition = {
      ...mockData.credentialDefinition,
      types: mockData.credentialDefinition.type
    };

    // wallet / client receives credential
    const result = await client.requestCredential({
      credentialDefinition,
      agent
    });
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches static DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);
  });

  it('should fail when reusing a completed exchange', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OID4VCI issuance initiation URL
    through a CHAPI OID4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    const {openIdUrl: issuanceUrl} = await helpers.createCredentialOffer({
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
    const chapiRequest = {OID4VCI: issuanceUrl};
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
    const result = await client.requestCredential({
      credentialDefinition: mockData.credentialDefinition,
      agent
    });
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches static DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(
      'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);

    // now try to reuse the exchange
    let err;
    try {
      await client.requestCredential({
        credentialDefinition: mockData.credentialDefinition,
        agent
      });
    } catch(error) {
      err = error;
    }
    should.exist(err);
    should.equal(err?.cause?.data?.error, 'duplicate_error');
  });
});
