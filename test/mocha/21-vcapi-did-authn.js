/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {v4 as uuid} from 'uuid';

const {
  baseUrl, didAuthnCredentialTemplate, genericCredentialTemplate
} = mockData;

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
      // FIXME: add test with a `requiredDid` -- any presented VPs must include
      // DID Authn with a DID that matches the `requiredDid` value -- however,
      // this might be generalized into some other kind of VPR satisfaction
      // mechanism
    });

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
    should.exist(response?.data?.verifiablePresentation);
    // ensure DID in VC matches `did`
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);
  });

  it('should pass when sending VP in second call', async () => {
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
    should.exist(vprResponse?.data?.verifiablePresentationRequest);

    // generate VP
    const {domain, challenge} = vprResponse.data.verifiablePresentationRequest;
    const {verifiablePresentation, did} = await helpers.createDidAuthnVP(
      {domain, challenge});

    // post VP to get VP w/VCs in response
    const vpResponse = await httpClient.post(
      url, {agent, json: {verifiablePresentation}});
    should.exist(vpResponse?.data?.verifiablePresentation);
    const {verifiablePresentation: vp} = vpResponse.data;
    // ensure DID in VC matches `did`
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);

    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });
});

describe('exchange w/ VC-API delivery + DID authn + generic template', () => {
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
      template: genericCredentialTemplate
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
      exchangerRootZcap,
      variables: {
        credentialId,
        vc: `{
            '@context': [
              'https://www.w3.org/2018/credentials/v1',
              'https://www.w3.org/2018/credentials/examples/v1'
            ],
            'id': $credentialId,
            'issuanceDate': $issuanceDate,
            'type': [
              'VerifiableCredential',
              'UniversityDegreeCredential'
            ],
            'credentialSubject': {
              'id': $results.didAuthn.did,
              'degree': {
                'type': 'BachelorDegree',
                'name': 'Bachelor of Science and Arts'
              }
            }
          }`
      }
      // FIXME: add test with a `requiredDid` -- any presented VPs must include
      // DID Authn with a DID that matches the `requiredDid` value -- however,
      // this might be generalized into some other kind of VPR satisfaction
      // mechanism
    });

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
    should.exist(response?.data?.verifiablePresentation);
    // ensure DID in VC matches `did`
    const {verifiablePresentation: vp} = response.data;
    should.exist(vp?.verifiableCredential?.[0]?.credentialSubject?.id);
    const {verifiableCredential: [vc]} = vp;
    vc.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(vc.id);
    vc.id.should.equal(credentialId);
  });
});

describe('exchange w/ VC-API presentation + templated DID authn', () => {
  let capabilityAgent;
  let exchangerId;
  let exchangerRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      exchangerCreateChallengeZcap,
      exchangerVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create exchanger instance w/ oauth2-based authz
    const zcaps = {
      createChallenge: exchangerCreateChallengeZcap,
      verifyPresentation: exchangerVerifyPresentationZcap
    };
    // require semantically-named exchanger steps
    const steps = {
      // DID Authn step
      didAuthn: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "createChallenge": true,
            "verifiablePresentationRequest": {
              "query": query,
              "domain": domain
            }
          }`
        }
      }
    };
    // set initial step
    const initialStep = 'didAuthn';
    const exchangerConfig = await helpers.createExchangerConfig({
      capabilityAgent, zcaps, steps, initialStep
    });
    exchangerId = exchangerConfig.id;
    exchangerRootZcap = `urn:zcap:root:${encodeURIComponent(exchangerId)}`;
  });

  it('should pass', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        query: {
          type: 'DIDAuthentication',
          acceptedMethods: [{method: 'key'}]
        },
        domain: baseUrl
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${exchangerId}/exchanges`,
      capabilityAgent, capability: exchangerRootZcap, exchange
    });

    // post to exchange URL to get expected VPR
    let response = await httpClient.post(
      exchangeId, {agent, json: {}});
    should.exist(response?.data?.verifiablePresentationRequest);
    const {data: {verifiablePresentationRequest: vpr}} = response;
    const expectedVpr = {
      query: {
        type: 'DIDAuthentication',
        acceptedMethods: [{method: 'key'}]
      },
      domain: baseUrl
    };
    expectedVpr.query.should.deep.equal(vpr.query);
    expectedVpr.domain.should.deep.equal(vpr.domain);
    should.exist(vpr.challenge);

    // generate VP
    const {domain, challenge} = vpr;
    const {verifiablePresentation, did} = await helpers.createDidAuthnVP(
      {domain, challenge});

    response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    // should be no VP nor VPR in the response, indicating the end of the
    // exchange (and nothing was issued, just presented)
    should.not.exist(response?.data?.verifiablePresentation);
    should.not.exist(response?.data?.verifiablePresentationRequest);

    // exchange should be complete and contain the submitted VPR
    // exchange state should be complete
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
