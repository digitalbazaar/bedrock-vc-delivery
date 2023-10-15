/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {oid4vp} from '@digitalbazaar/oid4-client';

const {baseUrl} = mockData;
const {getAuthorizationRequest} = oid4vp;

describe('exchange w/ OID4VP presentation w/DID Authn only', () => {
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
      capabilityAgent, zcaps, steps, initialStep, oauth2: true
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
      url: `${exchangerId}/exchanges`,
      capabilityAgent, capability: exchangerRootZcap, exchange
    });

    // get authorization request
    const authzReqUrl = `${exchangeId}/openid/client/authorization/request`;
    const {authorizationRequest} = await getAuthorizationRequest(
      {url: authzReqUrl, agent});

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

    // create presentation submission
    const {presentationSubmission} = oid4vp.createPresentationSubmission({
      presentationDefinition: authorizationRequest.presentation_definition,
      verifiablePresentation
    });

    // FIXME: use oid4-client for this
    const body = new URLSearchParams();
    body.set('vp_token', JSON.stringify(verifiablePresentation));
    body.set('presentation_submission', JSON.stringify(presentationSubmission));
    const response = await httpClient.post(authorizationRequest.response_uri, {
      agent, body, headers: {accept: 'application/json'}
    });
    // should be only an optional `redirect_uri` in the response
    should.exist(response);
    should.exist(response.data);
    //should.exist(response.data.redirect_uri);

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
