/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const {credentialTemplate} = mockData;

describe('exchange w/ VC-API delivery', () => {
  let capabilityAgent;
  let exchangerId;
  let exchangerRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      exchangerIssueZcap,
      exchangerCredentialStatusZcap,
      exchangerCreateChallengeZcap,
      exchangerVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create exchanger instance w/ oauth2-based authz
    const zcaps = {
      issue: exchangerIssueZcap,
      credentialStatus: exchangerCredentialStatusZcap,
      createChallenge: exchangerCreateChallengeZcap,
      verifyPresentation: exchangerVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: credentialTemplate
    }];
    const exchangerConfig = await helpers.createExchangerConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    exchangerId = exchangerConfig.id;
    exchangerRootZcap = `urn:zcap:root:${encodeURIComponent(exchangerId)}`;
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
      exchangerId,
      exchangerRootZcap
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
      exchangerId,
      exchangerRootZcap
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

    // now try to reuse the exchange
    let err;
    try {
      await httpClient.post(url, {agent, json: {}});
    } catch(error) {
      err = error;
    }
    should.exist(err);
    should.equal(err?.data?.name, 'DuplicateError');
  });
});
