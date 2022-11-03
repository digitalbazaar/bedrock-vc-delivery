/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {createRequire} from 'node:module';
import {mockData} from './mock.data.js';
const require = createRequire(import.meta.url);

const {baseUrl} = mockData;

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('exchange w/ VC-API delivery + DID authn', () => {
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
      template: JSON.stringify(mockCredential)
    }];
    // require semantically-named exchanger steps
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
    const exchangerConfig = await helpers.createExchangerConfig({
      capabilityAgent, zcaps, credentialTemplates, steps, initialStep,
      oauth2: true
    });
    exchangerId = exchangerConfig.id;
    exchangerRootZcap = `urn:zcap:root:${encodeURIComponent(exchangerId)}`;
  });

  it('should pass when sending VP in single call', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    const {exchangeId} = await helpers.createCredentialOffer({
      // FIXME: identify target user in local system
      userId: 'urn:123',
      credentialType: 'https://did.example.org/healthCard',
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      exchangerId,
      exchangerRootZcap
      // FIXME: add test with a `requiredDid` -- any presented VPs must include
      // DID Authn with a DID that matches the `requiredDid` value -- however,
      // this might be generalized into some other kind of VPR satisfaction
      // mechanism
    });
    console.log('exchangeId', exchangeId);

    const chapiRequest = {
      VerifiablePresentation: {
        query: {
          type: 'DIDAuthentication'
        },
        challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
        domain: baseUrl,
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

    // generate VP
    const {domain, challenge} = parsedChapiRequest.VerifiablePresentation;
    const {verifiablePresentation, did} = await helpers.createDidAuthnVP(
      {domain, challenge});

    // post VP to get VP in response
    const {
      VerifiablePresentation: {
        interact: {
          service: [{serviceEndpoint: url}]
        }
      }
    } = parsedChapiRequest;
    const response = await httpClient.post(
      url, {agent, json: {verifiablePresentation}});
    console.log('response.data', response.data);
    should.exist(response?.data?.verifiablePresentation);

    // FIXME: assert on result
    // FIXME: assert DID in VC matches `did`
  });

  it('should pass when sending VP in second call', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    const {exchangeId} = await helpers.createCredentialOffer({
      // FIXME: identify target user in local system
      userId: 'urn:123',
      credentialType: 'https://did.example.org/healthCard',
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      exchangerId,
      exchangerRootZcap
    });
    console.log('exchangeId', exchangeId);

    const chapiRequest = {
      VerifiablePresentation: {
        query: {
          type: 'DIDAuthentication'
        },
        challenge: '3182bdea-63d9-11ea-b6de-3b7c1404d57f',
        domain: baseUrl,
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

    // post empty body to get VPR in response
    const {
      VerifiablePresentation: {
        interact: {
          service: [{serviceEndpoint: url}]
        }
      }
    } = parsedChapiRequest;
    const vprResponse = await httpClient.post(url, {agent, json: {}});
    console.log('vprResponse.data', vprResponse.data);
    should.exist(vprResponse?.data?.verifiablePresentationRequest);

    // generate VP
    const {domain, challenge} = vprResponse.data.verifiablePresentationRequest;
    console.log('domain', domain);
    const {verifiablePresentation, did} = await helpers.createDidAuthnVP(
      {domain, challenge});

    // FIXME: post VP to get  VP w/VCs in response
    const vpResponse = await httpClient.post(
      url, {agent, json: {verifiablePresentation}});
    console.log('vpResponse.data', vpResponse.data);
    should.exist(vpResponse?.data?.verifiablePresentation);

    // FIXME: assert on result
    // FIXME: assert DID in VC matches `did`
  });
});
