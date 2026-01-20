/*!
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {importJWK} from 'jose';
import {mockData} from './mock.data.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {randomUUID as uuid} from 'node:crypto';

const {baseUrl, alumniCredentialTemplate} = mockData;
const {getAuthorizationRequest} = oid4vp;

describe('exchange w/ OID4VP "direct.jwt" + signed AR', () => {
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
  let signAuthorizationRequestRefId;
  let authorizationRequestPublicKeyJwk;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create OID4VP authz request signing params
    const authzRequestSigningParams = await helpers
      .createWorkflowOid4vpAuthzRequestSigningParams({
        capabilityAgent
      });
    ({authorizationRequestPublicKeyJwk} = authzRequestSigningParams);
    const {signAuthorizationRequestZcap} = authzRequestSigningParams;

    // create workflow instance w/ oauth2-based authz
    signAuthorizationRequestRefId = `urn:uuid:${uuid()}`;
    const zcaps = {
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap,
      [signAuthorizationRequestRefId]: signAuthorizationRequestZcap
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
            }],
          }],
          domain: baseUrl
        },
        openId: {
          // use `clientProfiles`
          clientProfiles: {
            // just use `default` client profile, no others
            default: {
              createAuthorizationRequest: 'authorizationRequest',
              response_mode: 'direct_post.jwt',
              // enable signed authz request
              client_metadata: {
                require_signed_request_object: true
              },
              zcapReferenceIds: {
                signAuthorizationRequest: signAuthorizationRequestRefId
              }
            }
          }
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });
    const authzReqUrl =
      `${exchangeId}/openid/clients/default/authorization/request`;

    const getVerificationKey = async ({protectedHeader}) => {
      if(protectedHeader.kid !== authorizationRequestPublicKeyJwk.kid) {
        throw new Error(`Key "${protectedHeader.kid}" not found.`);
      }
      return importJWK(authorizationRequestPublicKeyJwk);
    };

    // confirm oid4vp URL matches the one in `protocols`
    let authzRequestFromOid4vpUrl;
    {
      // `openid4vp` URL would be:
      const searchParams = new URLSearchParams({
        client_id:
          `${exchangeId}/openid/clients/default/authorization/response`,
        request_uri: authzReqUrl
      });
      const openid4vpUrl = 'openid4vp://?' + searchParams.toString();

      const protocolsUrl = `${exchangeId}/protocols`;
      const response = await httpClient.get(protocolsUrl, {agent});
      should.exist(response);
      should.exist(response.data);
      should.exist(response.data.protocols);
      should.exist(response.data.protocols.vcapi);
      response.data.protocols.vcapi.should.equal(exchangeId);
      should.exist(response.data.protocols.OID4VP);
      response.data.protocols.OID4VP.should.equal(openid4vpUrl);

      ({
        authorizationRequest: authzRequestFromOid4vpUrl
      } = await getAuthorizationRequest({
        url: openid4vpUrl, getVerificationKey, agent
      }));
    }

    // get authorization request
    const {authorizationRequest} = await getAuthorizationRequest(
      {url: authzReqUrl, getVerificationKey, agent});

    should.exist(authorizationRequest);
    should.exist(authorizationRequest.presentation_definition);
    authorizationRequest.presentation_definition.id.should.be.a('string');
    authorizationRequest.presentation_definition.input_descriptors.should.be
      .an('array');
    authorizationRequest.response_mode.should.equal('direct_post.jwt');
    authorizationRequest.nonce.should.be.a('string');
    // FIXME: add assertions for `authorizationRequest.presentation_definition`

    // ensure authz request matches the one from OID4VP URL
    authzRequestFromOid4vpUrl.should.deep.equal(authorizationRequest);

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
    helpers.assertVpr({
      actual: verifiablePresentationRequest, expected: expectedVpr
    });

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
