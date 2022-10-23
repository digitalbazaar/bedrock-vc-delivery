/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {createRequire} from 'node:module';
import {httpClient} from '@digitalbazaar/http-client';
import {klona} from 'klona';
import {mockData} from './mock.data.js';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('exchange w/ VC-API delivery', () => {
  let capabilityAgent;
  let exchangerConfig;
  let exchangerId;
  let exchangerRootZcap;
  let exchangerIssueZcap;
  let exchangerCredentialStatusZcap;
  let exchangerVerifyPresentationZcap;
  beforeEach(async () => {
    ({
      exchangerIssueZcap, exchangerCredentialStatusZcap,
      exchangerVerifyPresentationZcap,
      capabilityAgent
    } = await helpers.provisionDependencies());

    // create exchanger instance w/ oauth2-based authz
    const zcaps = {
      issue: exchangerIssueZcap,
      credentialStatus: exchangerCredentialStatusZcap,
      verifyPresentation: exchangerVerifyPresentationZcap
    };
    exchangerConfig = await helpers.createExchangerConfig(
      {capabilityAgent, zcaps, oauth2: true});
    exchangerId = exchangerConfig.id;
    exchangerRootZcap = `urn:zcap:root:${encodeURIComponent(exchangerId)}`;
  });

  it('delivery w/o DID Authn', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // FIXME: first, create an exchange with a VC template and indicate that
    // a DID Authn proof is required
    // use `exchangerRootZcap` to create exchange
    // ... might need to pass a query param for the protocol to the exchange
    // ... otherwise it won't be clear what kind of response should be sent
    // FIXME: the exchange ID must have an exchanger ID in the path (for now)
    // ... the reason for this is to allow the exchange to have access to
    // whatever authz tokens / zcaps it needs to use verifier/issuer instances
    // that need only be configured once per exchanger (and used many times
    // per exchange)
    // FIXME:
    const exchangeId = `${exchangerId}/exchanges/<exchangeId>`;

    const chapiRequest = {
      VerifiablePresentation: {
        interact: {
          service: [{
            type: 'VerifiableCredentialApiExchangeService',
            // FIXME: add transaction ID?
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

    // FIXME: call helper to post empty body and get VP w/VCs in response

    // FIXME: assert on result
  });

  it('delivery w/ DID Authn', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing a DID Authn request and interact VC-API
    exchange URL through CHAPI. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // FIXME: first, create an exchange with a VC template and indicate that
    // a DID Authn proof is required
    // use `exchangerRootZcap` to create exchange
    // ... might need to pass a query param for the protocol to the exchange
    // ... otherwise it won't be clear what kind of response should be sent
    // FIXME: the exchange ID must have an exchanger ID in the path (for now)
    // ... the reason for this is to allow the exchange to have access to
    // whatever authz tokens / zcaps it needs to use verifier/issuer instances
    // that need only be configured once per exchanger (and used many times
    // per exchange)
    // FIXME:
    const exchangeId = `${exchangerId}/exchanges/<exchangeId>`;

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
            // FIXME: add transaction ID?
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

    // FIXME: digitally-sign VP w/DID authn proof

    // FIXME: update with real signer
    const didProofSigner = {
      algorithm: 'EdDSA', id: 'did:key:1234#5678',
      async sign(data) {
        return new Uint8Array(64);
      }
    };

    // FIXME: call helper to post VP and get VP w/VCs in response

    // FIXME: assert on result
  });
});
