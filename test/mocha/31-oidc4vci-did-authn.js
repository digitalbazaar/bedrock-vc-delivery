/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {
  OIDC4VCIClient, parseInitiateIssuanceUrl
} from '@digitalbazaar/oidc4vci-client';
import {agent} from '@bedrock/https-agent';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const {baseUrl, didAuthnCredentialTemplate} = mockData;

describe('exchange w/OIDC4VCI delivery + DID authn', () => {
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
      template: didAuthnCredentialTemplate
    }];
    // require semantically-named exchanger steps
    const steps = {
      // DID Authn step
      didAuthn: {
        createChallenge: true,
        // will be used by VC-API
        verifiablePresentationRequest: {
          query: {
            type: 'DIDAuthentication',
            acceptedMethods: [{method: 'key'}]
          },
          domain: baseUrl
        },
        // will be used by OIDC4VCI
        jwtDidProofRequest: {
          acceptedMethods: [{method: 'key'}]
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

  it('should pass w/ pre-authorized code flow', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    /* This flow demonstrates passing an OIDC4VCI issuance initiation URL
    through a CHAPI OIDC4VCI request. The request is passed to a "Claimed URL"
    which was registered on a user's device by a native app. The native app's
    domain also published a "manifest.json" file that expressed the same
    "Claimed URL" via `credential_handler.url='https://myapp.example/ch'` and
    `credential_handler.launchType='redirect'` (TBD). */

    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    const {oidc4vciUrl: issuanceUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialType: 'https://did.example.org/healthCard',
      credentialId,
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
    const chapiRequest = {OIDC4VCI: issuanceUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const initiateIssuanceInfo = parseInitiateIssuanceUrl(
      {url: parsedChapiRequest.OIDC4VCI});

    // wallet / client gets access token
    const {issuer, preAuthorizedCode} = initiateIssuanceInfo;
    const client = await OIDC4VCIClient.fromPreAuthorizedCode({
      issuer, preAuthorizedCode, agent
    });

    const {did, signer: didProofSigner} = await helpers.createDidProofSigner();

    // wallet / client receives credential
    const result = await client.requestDelivery({
      did,
      didProofSigner,
      agent
    });
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches generated DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);
  });

  it.skip('should pass w/ wallet-initiated flow', async () => {
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

    // FIXME: wallet / client sends request for a credential
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

    // FIXME: wallet / client receives response
    /*
    HTTP/1.1 302 Found
    Location: https://server.example.com/authorize?
      response_type=code
      &client_id=s6BhdRkqt3
      &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
      &code_challenge_method=S256
      &authorization_details=...

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
    //const url = '';

    // FIXME: implement OIDC4VCIClient.fromAuthorizationCode()
    //const client = await OIDC4VCIClient.fromAuthorizationCode({url, agent});

    // FIXME: request delivery
    //const result = await client.requestDelivery();
    // FIXME: assert on result
  });
});
