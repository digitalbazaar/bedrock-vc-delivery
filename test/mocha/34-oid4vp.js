/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {v4 as uuid} from 'uuid';

const {baseUrl, alumniCredentialTemplate} = mockData;
const {getAuthorizationRequest} = oid4vp;

describe('exchange w/ OID4VP presentation w/DID Authn only', () => {
  let capabilityAgent;
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    const zcaps = {
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    // require semantically-named workflow steps
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
              "client_id": globals.workflow.id &
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
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, steps, initialStep, oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        verifiablePresentationRequest: {
          query: {
            type: 'DIDAuthentication',
            acceptedMethods: [{method: 'key'}],
            acceptedCryptosuites: [{cryptosuite: 'Ed25519Signature2020'}]
          },
          domain: baseUrl
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });

    // request URI
    const authzReqUrl = `${exchangeId}/openid/client/authorization/request`;

    // `openid4vp` URL would be:
    /*
    const searchParams = new URLSearchParams({
      client_id: `${exchangeId}/openid/client/authorization/response`,
      request_uri: authzReqUrl
    });
    const openid4vpUrl = 'openid4vp://authorize?' + searchParams.toString();*/

    // exchange state should be pending
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('pending');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }

    // get authorization request
    const {authorizationRequest} = await getAuthorizationRequest(
      {url: authzReqUrl, agent});

    // exchange state should be active
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('active');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }

    should.exist(authorizationRequest);
    should.exist(authorizationRequest.presentation_definition);
    authorizationRequest.presentation_definition.id.should.be.a('string');
    authorizationRequest.presentation_definition.input_descriptors.should.be
      .an('array');
    authorizationRequest.response_mode.should.equal('direct_post');
    authorizationRequest.nonce.should.be.a('string');

    // generate VPR from authorization request
    const {verifiablePresentationRequest} = await oid4vp.toVpr(
      {authorizationRequest});

    // generate VP
    const {domain, challenge} = verifiablePresentationRequest;
    const {verifiablePresentation, did} = await helpers.createDidAuthnVP(
      {domain, challenge});

    // send authorization response
    const {
      result, presentationSubmission
    } = await oid4vp.sendAuthorizationResponse({
      verifiablePresentation, authorizationRequest, agent
    });
    // should be only an optional `redirect_uri` in the response
    should.exist(result);
    //should.exist(result.redirect_uri);

    // exchange should be complete and contain the VP and open ID results
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
  });
});

describe('exchange w/ OID4VP presentation w/VC', () => {
  // issue VC for use with OID4VP
  let verifiableCredential;
  before(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      capabilityAgent,
      workflowIssueZcap,
      workflowCredentialStatusZcap,
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;

    // create workflow instance to issue VCs
    const zcaps = {
      issue: workflowIssueZcap,
      credentialStatus: workflowCredentialStatusZcap,
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: alumniCredentialTemplate
    }];
    const workflowConfig = await helpers.createWorkflowConfig(
      {capabilityAgent, zcaps, credentialTemplates, oauth2: true});
    const workflowId = workflowConfig.id;
    const workflowRootZcap =
      `urn:zcap:root:${encodeURIComponent(workflowId)}`;

    // create exchange to issue VC
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.credentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });

    // post empty body and get VP w/VCs in response
    const response = await httpClient.post(exchangeId, {agent, json: {}});
    const {verifiablePresentation: vp} = response.data;
    ({verifiableCredential: [verifiableCredential]} = vp);
  });

  let capabilityAgent;
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    const zcaps = {
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    // require semantically-named workflow steps
    const steps = {
      myStep: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "createChallenge": true,
            "verifiablePresentationRequest": verifiablePresentationRequest,
            "openId": openId
          }`
        }
      }
    };
    // set initial step
    const initialStep = 'myStep';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, steps, initialStep, oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        verifiablePresentationRequest: {
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
                type: 'AlumniCredential'
              }
            }],
          }],
          domain: baseUrl
        },
        openId: {
          createAuthorizationRequest: 'authorizationRequest'
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });
    const authzReqUrl = `${exchangeId}/openid/client/authorization/request`;

    // `openid4vp` URL would be:
    /*const searchParams = new URLSearchParams({
      client_id: `${exchangeId}/openid/client/authorization/response`,
      request_uri: authzReqUrl
    });
    const openid4vpUrl = 'openid4vp://authorize?' + searchParams.toString();
    console.log('openid4vpUrl', openid4vpUrl);*/

    // get authorization request
    const {authorizationRequest} = await getAuthorizationRequest(
      {url: authzReqUrl, agent});

    should.exist(authorizationRequest);
    should.exist(authorizationRequest.presentation_definition);
    authorizationRequest.presentation_definition.id.should.be.a('string');
    authorizationRequest.presentation_definition.input_descriptors.should.be
      .an('array');
    authorizationRequest.response_mode.should.equal('direct_post');
    authorizationRequest.nonce.should.be.a('string');
    // FIXME: add assertions for `authorizationRequest.presentation_definition`

    // generate VPR from authorization request
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
            type: 'AlumniCredential'
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
    const {verifiablePresentation, did} = await helpers.createDidAuthnVP(
      {domain, challenge, verifiableCredential});

    // send authorization response
    const {
      result, presentationSubmission
    } = await oid4vp.sendAuthorizationResponse({
      verifiablePresentation, authorizationRequest, agent
    });
    // should be only an optional `redirect_uri` in the response
    should.exist(result);
    //should.exist(result.redirect_uri);

    // exchange should be complete and contain the VP and open ID results
    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.myStep);
        should.exist(
          exchange?.variables?.results?.myStep?.verifiablePresentation);
        exchange?.variables?.results?.myStep.did.should.equal(did);
        exchange.variables.results.myStep.verifiablePresentation
          .should.deep.equal(verifiablePresentation);
        should.exist(exchange.variables.results.myStep.openId);
        exchange.variables.results.myStep.openId.authorizationRequest
          .should.deep.equal(authorizationRequest);
        exchange.variables.results.myStep.openId.presentationSubmission
          .should.deep.equal(presentationSubmission);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });
});
