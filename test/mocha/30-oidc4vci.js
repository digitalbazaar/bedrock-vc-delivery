/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {createRequire} from 'node:module';
import {OIDC4VCIClient} from './OIDC4VCIClient.js';
const require = createRequire(import.meta.url);

// NOTE: using embedded context in mockCredential:
// https://www.w3.org/2018/credentials/examples/v1
const mockCredential = require('./mock-credential.json');

describe('exchange w/OIDC4VCI delivery', () => {
  let capabilityAgent;
  let exchangerId;
  let exchangerRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      exchangerIssueZcap,
      exchangerCredentialStatusZcap,
      exchangerVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create exchanger instance w/ oauth2-based authz
    const zcaps = {
      issue: exchangerIssueZcap,
      credentialStatus: exchangerCredentialStatusZcap,
      verifyPresentation: exchangerVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: JSON.stringify(mockCredential)
    }];
    const exchangerConfig = await helpers.createExchangerConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    exchangerId = exchangerConfig.id;
    exchangerRootZcap = `urn:zcap:root:${encodeURIComponent(exchangerId)}`;
  });

  it('should pass w/ pre-authorized code flow', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OIDC4VCI issuance initiation URL
    through a CHAPI OIDC4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const {
      oidc4vciUrl: issuanceUrl,
      exchangeId
    } = await helpers.createCredentialOffer({
      // FIXME: identify target user in local system
      userId: 'urn:123',
      credentialType: 'https://did.example.org/healthCard',
      preAuthorized: true,
      userPinRequired: true,
      capabilityAgent,
      exchangerId,
      exchangerRootZcap
    });
    console.log('exchangeId', exchangeId);
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
    // FIXME: add negative tests that use invalid and missing access tokens
    const {issuer, preAuthorizedCode} = initiateIssuanceInfo;
    const client = await OIDC4VCIClient.fromPreAuthorizedCode({
      issuer, preAuthorizedCode, userPin, agent
    });

    // FIXME: wallet receives credential
    const result = await client.requestDelivery({agent});
    // FIXME: assert on result
  });

  it('should pass w/ wallet-initiated flow', async () => {
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
