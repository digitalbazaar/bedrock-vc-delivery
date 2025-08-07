/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {OID4Client, parseCredentialOfferUrl} from '@digitalbazaar/oid4-client';
import {agent} from '@bedrock/https-agent';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const {credentialTemplate} = mockData;
const credentialFormat = 'jwt_vc_json-ld';

describe('exchange w/OID4VCI delivery of VC-JWT', () => {
  let capabilityAgent;
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies({
      issuerOptions: {
        issueOptions: {
          // cryptosuites: [{
          //   name: 'Ed25519Signature2020'
          // }]
          envelope: {
            format: 'VC-JWT',
            algorithm: 'Ed25519',
            // works with or without options, but `EdDSA` will be chosen
            // over `Ed25519` if `alg` not given an an Ed25519 key is used
            /*options: {
              alg: 'Ed25519'
            }*/
          }
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
    const configOptions = {
      credentialTemplates,
      issuerInstances: [{
        supportedFormats: ['jwt_vc_json-ld'],
        zcapReferenceIds: {
          issue: 'issue'
        }
      }]
    };
    const workflowConfig = await helpers.createWorkflowConfig(
      {capabilityAgent, zcaps, configOptions, oauth2: true});
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
      credentialFormat,
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
    const result = await client.requestCredential({
      credentialDefinition: mockData.credentialDefinition,
      agent,
      format: credentialFormat
    });
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal(credentialFormat);
    result.credential.should.be.a('string');
    // FIXME: add additional assertions after parsing JWT
    // // ensure credential subject ID matches static DID
    // should.exist(result.credential?.credentialSubject?.id);
    // result.credential.credentialSubject.id.should.equal(
    //   'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // // ensure VC ID matches
    // should.exist(result.credential.id);
    // result.credential.id.should.equal(credentialId);

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
      credentialFormat,
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
      agent,
      format: credentialFormat
    });
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal(credentialFormat);
    result.credential.should.be.a('string');
    // FIXME: add additional assertions after parsing JWT

    // // ensure credential subject ID matches static DID
    // should.exist(result.credential?.credentialSubject?.id);
    // result.credential.credentialSubject.id.should.equal(
    //   'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // // ensure VC ID matches
    // should.exist(result.credential.id);
    // result.credential.id.should.equal(credentialId);
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
      credentialFormat,
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
      agent,
      format: credentialFormat
    });
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal(credentialFormat);
    result.credential.should.be.a('string');
    // FIXME: add additional assertions after parsing JWT
    // // ensure credential subject ID matches static DID
    // should.exist(result.credential?.credentialSubject?.id);
    // result.credential.credentialSubject.id.should.equal(
    //   'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // // ensure VC ID matches
    // should.exist(result.credential.id);
    // result.credential.id.should.equal(credentialId);
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
      credentialFormat,
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
      agent,
      format: credentialFormat
    });
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal(credentialFormat);
    result.format.should.equal(credentialFormat);
    result.credential.should.be.a('string');
    // FIXME: add additional assertions after parsing JWT
    // // ensure credential subject ID matches static DID
    // should.exist(result.credential?.credentialSubject?.id);
    // result.credential.credentialSubject.id.should.equal(
    //   'did:example:ebfeb1f712ebc6f1c276e12ec21');
    // // ensure VC ID matches
    // should.exist(result.credential.id);
    // result.credential.id.should.equal(credentialId);

    // now try to reuse the exchange
    let err;
    try {
      await client.requestCredential({
        credentialDefinition: mockData.credentialDefinition,
        agent,
        format: credentialFormat
      });
    } catch(error) {
      err = error;
    }
    should.exist(err);
    should.equal(err?.cause?.data?.error, 'duplicate_error');
  });
});
