/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {OID4Client, parseInitiateIssuanceUrl} from '@digitalbazaar/oid4-client';
import {agent} from '@bedrock/https-agent';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const {credentialTemplate} = mockData;

describe('exchange w/batch OID4VCI delivery', () => {
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
      template: credentialTemplate.replace(
        'credentialId', 'credentialId1')
    }, {
      type: 'jsonata',
      template: credentialTemplate.replace(
        'credentialId', 'credentialId2')
    }];
    const exchangerConfig = await helpers.createExchangerConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    exchangerId = exchangerConfig.id;
    exchangerRootZcap = `urn:zcap:root:${encodeURIComponent(exchangerId)}`;
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
    const {openIdUrl: issuanceUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialType: [
        'https://did.example.org/healthCard',
        'https://did.example.org/healthCard'
      ],
      variables: {
        credentialId1,
        credentialId2
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      exchangerId,
      exchangerRootZcap
    });
    const chapiRequest = {OID4VC: issuanceUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const initiateIssuanceInfo = parseInitiateIssuanceUrl(
      {url: parsedChapiRequest.OID4VC});

    // wallet / client gets access token
    const {issuer, preAuthorizedCode} = initiateIssuanceInfo;
    const client = await OID4Client.fromPreAuthorizedCode({
      issuer, preAuthorizedCode, agent
    });

    // wallet / client requests credentials
    const result = await client.requestCredentials({
      requests: [{
        type: 'https://did.example.org/healthCard'
      }, {
        type: 'https://did.example.org/healthCard'
      }],
      agent
    });
    should.exist(result);
    result.should.have.keys(['credential_responses']);
    result.credential_responses.should.be.an('array');
    result.credential_responses.length.should.equal(2);
    result.credential_responses.forEach(cr => {
      cr.should.include.keys(['format', 'credential']);
      cr.format.should.equal('ldp_vc');
      // ensure credential subject ID matches static DID
      should.exist(cr.credential?.credentialSubject?.id);
      cr.credential.credentialSubject.id.should.equal(
        'did:example:ebfeb1f712ebc6f1c276e12ec21');
    });
    result.credential_responses[0].credential.id.should.equal(credentialId1);
    result.credential_responses[1].credential.id.should.equal(credentialId2);
  });
});
