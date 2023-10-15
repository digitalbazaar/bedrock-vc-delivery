/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
// FIXME: remove if no longer used
//import {httpClient} from '@digitalbazaar/http-client';
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
                "/client/authorization/response"
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

    // FIXME: remove me
    //console.log('authorizationRequest', authorizationRequest);

    should.exist(authorizationRequest);
    should.exist(authorizationRequest.presentation_definition);
    authorizationRequest.presentation_definition.id.should.be.a('string');
    authorizationRequest.presentation_definition.input_descriptors.should.be
      .an('array');
    authorizationRequest.response_mode.should.equal('direct_post');
    authorizationRequest.nonce.should.be.a('string');

    // generate VPR from authorization request
    //const vpr = await oid4vp.toVpr({authorizationRequest});
    // FIXME: remove me
    //console.log('vpr', JSON.stringify(vpr, null, 2));

    /*

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
    }*/
  });
});
