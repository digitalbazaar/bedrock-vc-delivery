/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {OID4Client, parseCredentialOfferUrl} from '@digitalbazaar/oid4-client';
import {agent} from '@bedrock/https-agent';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const {baseUrl, didAuthnCredentialTemplate} = mockData;

describe('exchanger backwards-compatibility: ' +
  'exchange w/batch OID4VCI delivery + DID authn', () => {
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
      template: didAuthnCredentialTemplate.replace(
        'credentialId', 'credentialId1')
    }, {
      type: 'jsonata',
      template: didAuthnCredentialTemplate.replace(
        'credentialId', 'credentialId2')
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
        // will be used by OID4VCI
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
      credentialDefinition: [
        mockData.credentialDefinition,
        mockData.credentialDefinition
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
      // FIXME: add test with a `requiredDid` -- any presented VPs must include
      // DID Authn with a DID that matches the `requiredDid` value -- however,
      // this might be generalized into some other kind of VPR satisfaction
      // mechanism
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
    const offer = parseCredentialOfferUrl({url: parsedChapiRequest.OID4VC});

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    const {did, signer: didProofSigner} = await helpers.createDidProofSigner();

    // wallet / client requests credentials
    const result = await client.requestCredentials({
      requests: [{
        credential_definition: mockData.credentialDefinition
      }, {
        credential_definition: mockData.credentialDefinition
      }],
      did,
      didProofSigner,
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
      cr.credential.credentialSubject.id.should.equal(did);
    });
    result.credential_responses[0].credential.id.should.equal(credentialId1);
    result.credential_responses[1].credential.id.should.equal(credentialId2);
  });
});
