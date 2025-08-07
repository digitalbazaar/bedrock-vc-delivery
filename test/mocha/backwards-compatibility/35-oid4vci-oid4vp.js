/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {
  OID4Client, oid4vp, parseCredentialOfferUrl
} from '@digitalbazaar/oid4-client';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

const {baseUrl, didAuthnCredentialTemplate} = mockData;

describe('exchanger backwards-compatibility: ' +
  'exchange w/OID4VCI delivery + OID4VP VC requirement', () => {
  let capabilityAgent;

  // provision a VC to use in the workflow below
  let verifiableCredential;
  let did;
  let signer;
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
    const workflowId = exchangerConfig.id;
    const workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;

    // use workflow to provision verifiable credential
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      exchangerId: workflowId,
      exchangerRootZcap: workflowRootZcap
    });

    // generate VP
    ({did, signer} = await helpers.createDidProofSigner());
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer
    });

    // post VP to get VP w/VC in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    const {verifiablePresentation: vp} = response.data;
    verifiableCredential = vp.verifiableCredential[0];
  });

  // provision workflow that will require the provisioned VC above
  let workflowId;
  let workflowRootZcap;
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
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "createChallenge": true,
            "verifiablePresentationRequest": verifiablePresentationRequest,
            "openId": {
              "createAuthorizationRequest": "authorizationRequest",
              "client_id_scheme": "redirect_uri",
              "client_id": globals.exchanger.id &
                "/exchanges/" &
                globals.exchange.id &
                "/openid/client/authorization/response"
            }
          }`
        }
      }
    };
    // set initial step
    const initialStep = 'didAuthn';
    const exchangerConfig = await helpers.createExchangerConfig({
      capabilityAgent, zcaps, credentialTemplates, steps, initialStep,
      oauth2: true
    });
    workflowId = exchangerConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass w/ pre-authorized code flow', async () => {
    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    const vpr = {
      query: [{
        type: 'DIDAuthentication',
        acceptedMethods: [{method: 'key'}],
        acceptedCryptosuites: [{cryptosuite: 'Ed25519Signature2020'}]
      }, {
        type: 'QueryByExample',
        credentialQuery: [{
          reason: 'We require a verifiable credential to pass this test',
          example: {
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://www.w3.org/2018/credentials/examples/v1'
            ],
            type: 'UniversityDegreeCredential'
          }
        }]
      }],
      domain: baseUrl
    };
    const {
      exchangeId,
      openIdUrl: issuanceUrl
    } = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      exchangerId: workflowId,
      exchangerRootZcap: workflowRootZcap,
      variables: {
        credentialId,
        verifiablePresentationRequest: vpr,
        openId: {
          createAuthorizationRequest: 'authorizationRequest'
        }
      }
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

    // wallet / client attempts to receive credential, should receive a
    // `presentation_required` error with an authorization request
    let error;
    try {
      await client.requestCredential({
        credentialDefinition: mockData.credentialDefinition,
        did,
        didProofSigner: signer,
        agent
      });
    } catch(e) {
      error = e;
    }
    should.exist(error);
    should.exist(error.cause);
    error.cause.name.should.equal('NotAllowedError');
    should.exist(error.cause.cause);
    error.cause.cause.data.error.should.equal('presentation_required');
    should.exist(error.cause.cause.data.authorization_request);

    // wallet / client responds to `authorization_request` by performing
    // OID4VP:
    let verifiablePresentation;
    {
      // generate VPR from authorization request
      const {
        cause: {
          cause: {data: {authorization_request: authorizationRequest}}
        }
      } = error;
      const {verifiablePresentationRequest} = await oid4vp.toVpr(
        {authorizationRequest});

      // VPR should be the same as the one from the exchange, modulo changes
      // comply with OID4VP spec
      const expectedVpr = {
        query: [{
          type: 'DIDAuthentication',
          // no OID4VP support for accepted DID methods at this time
          acceptedCryptosuites: [
            {cryptosuite: 'ecdsa-rdfc-2019'},
            {cryptosuite: 'eddsa-rdfc-2022'},
            {cryptosuite: 'Ed25519Signature2020'}
          ]
        }, {
          type: 'QueryByExample',
          credentialQuery: [{
            reason: 'We require a verifiable credential to pass this test',
            example: {
              '@context': [
                'https://www.w3.org/2018/credentials/v1',
                'https://www.w3.org/2018/credentials/examples/v1'
              ],
              type: 'UniversityDegreeCredential'
            }
          }]
        }],
        // OID4VP requires this to be the authz response URL
        domain: authorizationRequest.response_uri,
        // challenge should be set to authz nonce
        challenge: authorizationRequest.nonce
      };
      verifiablePresentationRequest.should.deep.equal(expectedVpr);

      // generate VP
      const {domain, challenge} = verifiablePresentationRequest;
      ({verifiablePresentation} = await helpers.createDidAuthnVP({
        domain, challenge,
        did, signer, verifiableCredential
      }));

      // send authorization response
      const {
        result, presentationSubmission
      } = await oid4vp.sendAuthorizationResponse({
        verifiablePresentation, authorizationRequest, agent
      });
      should.exist(result);

      // exchange should be `active` and contain the VP and open ID results
      {
        let err;
        try {
          const {exchange} = await helpers.getExchange(
            {id: exchangeId, capabilityAgent});
          should.exist(exchange?.state);
          exchange.state.should.equal('active');
          should.exist(exchange?.variables?.results?.didAuthn);
          should.exist(
            exchange?.variables?.results?.didAuthn?.verifiablePresentation);
          exchange?.variables?.results?.didAuthn.did.should.equal(did);
          exchange.variables.results.didAuthn.verifiablePresentation
            .should.deep.equal(verifiablePresentation);
          should.exist(exchange.variables.results.didAuthn.openId);
          exchange.variables.results.didAuthn.openId.authorizationRequest
            .should.deep.equal(authorizationRequest);
          exchange.variables.results.didAuthn.openId.presentationSubmission
            .should.deep.equal(presentationSubmission);
        } catch(error) {
          err = error;
        }
        should.not.exist(err);
      }
    }

    // wallet / client attempts to receive credential now that OID4VP is done
    let result;
    error = undefined;
    try {
      result = await client.requestCredential({
        credentialDefinition: mockData.credentialDefinition,
        did,
        didProofSigner: signer,
        agent
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal('ldp_vc');
    // ensure credential subject ID matches generated DID
    should.exist(result.credential?.credentialSubject?.id);
    result.credential.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(result.credential.id);
    result.credential.id.should.equal(credentialId);

    // exchange should be complete and contain the VP and original VC
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.didAuthn);
        should.exist(
          exchange?.variables?.results?.didAuthn?.verifiablePresentation);
        exchange?.variables?.results?.didAuthn.did.should.equal(did);
        exchange.variables.results.didAuthn.verifiablePresentation
          .should.deep.equal(verifiablePresentation);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });
});
