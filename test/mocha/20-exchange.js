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
import {OIDC4VCIClient} from './OIDC4VCIClient.js';

const require = createRequire(import.meta.url);

const {baseUrl} = mockData;

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe.only('exchange', () => {
  let capabilityAgent;
  let exchangerConfig;
  let exchangerId;
  let exchangerRootZcap;
  let exchangerIssueZcap;
  let exchangerVerifyPresentationZcap;
  beforeEach(async () => {
    ({
      exchangerIssueZcap, exchangerVerifyPresentationZcap, capabilityAgent
    } = await helpers.provisionDependencies());

    // create exchanger instance w/ oauth2-based authz
    const zcaps = {
      issue: exchangerIssueZcap,
      verifyPresentation: exchangerVerifyPresentationZcap
    };
    exchangerConfig = await helpers.createExchangerConfig(
      {capabilityAgent, zcaps, oauth2: true});
    exchangerId = exchangerConfig.id;
    exchangerRootZcap = `urn:zcap:root:${encodeURIComponent(exchangerId)}`;
  });

  it.only('pre-authorized code', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OIDC4VCI issuance initiation URL
    through a CHAPI OIDC4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // FIXME: first, create an exchange with a VC template and indicate that
    // a DID Authn proof is required and OIDC4VCI delivery is permitted;
    // use `exchangerRootZcap` to create exchange
    // ... might need to pass a query param for the protocol to the exchange
    // ... otherwise it won't be clear what kind of response should be sent
    // FIXME: ... so the exchange URL will need to be different for VC-API from
    // OIDC4VCI via a query param like `?p=oidc4vci` (and default to VC-API)
    // or perhaps add a path: `/oidc4vci`
    // FIXME: the exchange ID must have an exchanger ID in the path (for now)
    // ... the reason for this is to allow the exchange to have access to
    // whatever authz tokens / zcaps it needs to use verifier/issuer instances
    // that need only be configured once per exchanger (and used many times
    // per exchange)

    // pre-authorized flow, issuer-initiated
    const issuanceUrl = 'openid-initiate-issuance://?' +
        `issuer=${encodeURIComponent(baseUrl)}` +
        '&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard' +
        '&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA' +
        '&user_pin_required=true';
    const chapiRequest = {OIDC4VCI: issuanceUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    console.log('raw parsed URL', new URL(parsedChapiRequest.OIDC4VCI));
    const initiateIssuanceInfo = OIDC4VCIClient.parseInitiateIssuanceUrl(
      {url: parsedChapiRequest.OIDC4VCI});
    console.log('parsed initiate issuance info', initiateIssuanceInfo);

    // FIXME: get user pin if required
    const userPin = '493536';

    // FIXME: wallet gets access token
    const {issuer, preAuthorizedCode} = initiateIssuanceInfo;
    const client = await OIDC4VCIClient.fromPreAuthorizedCode({
      issuer, preAuthorizedCode, userPin, agent
    });

    // FIXME: update with real signer
    const didProofSigner = {
      algorithm: 'EdDSA', id: 'did:key:1234#5678',
      async sign(data) {
        return new Uint8Array(64);
      }
    };

    // FIXME: wallet receives credential
    const result = await client.requestDelivery({
      did: 'did:key:1234',
      didProofSigner,
      agent
    });
    // FIXME: assert on result
  });

  it('wallet-initiated', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    // FIXME: wallet sends request for a credential
    /*
    {
     "type":"openid_credential",
     "credential_type":"https://did.example.org/healthCard",
     "format":"ldp_vc",
     //"locations": ["aud1", "aud2", ...]
    }
    // ... OR ... request 2+ credentials
    [
      {
          "type":"openid_credential",
          "credential_type":"https://did.example.org/healthCard",
          "format":"ldp_vc"
      },
      {
          "type":"openid_credential",
          "credential_type":"https://did.example.org/mDL"
      }
    ]
    */

    // FIXME: wallet receives response
    /*
    HTTP/1.1 302 Found
    Location: https://server.example.com/authorize?
      response_type=code
      &client_id=s6BhdRkqt3
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
      &authorization_details=%5B%7B%22type%22:%22openid_credential%22,%22credential_type
      %22:%22https://did.example.org/healthCard%22,%22format%22:%22ldp_vc%22%7D,%7B%22ty
      pe%22:%22openid_credential%22,%22credential_type%22:%22https://did.example.org/mDL
      %22%7D%5D
      &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
      });

    ... OR ... scope option (map credential type to an oauth2 scope):

    HTTP/1.1 302 Found
    Location: https://server.example.com/authorize?
      response_type=code
      &scope=com.example.healthCardCredential
      &client_id=s6BhdRkqt3
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
      &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    */

    // FIXME: authorization responses:
    /*
    success:
    HTTP/1.1 302 Found
      Location: https://Wallet.example.org/cb?
        code=SplxlOBeZQQYbYS6WxSbIA

    failure:
    HTTP/1.1 302 Found
    Location: https://client.example.net/cb?
        error=invalid_request
        &error_description=Unsupported%20response_type%20value
    */
    const url = '';

    // FIXME: implement OIDC4VCIClient.fromAuthorizationCode()
    const client = await OIDC4VCIClient.fromAuthorizationCode({url, agent});

    // FIXME: request delivery
    const result = await client.requestDelivery();
    // FIXME: assert on result
  });
});
