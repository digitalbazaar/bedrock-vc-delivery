/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';

const {baseUrl} = mockData;

describe.skip('exchange w/ OID4VP + templated DID authn', () => {
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
      capabilityAgent, zcaps, steps, initialStep, oauth2: true
    });
    exchangerId = exchangerConfig.id;
    exchangerRootZcap = `urn:zcap:root:${encodeURIComponent(exchangerId)}`;
  });

  // FIXME: add tests that rely on VPR translation and tests that use
  // presentation definition directly
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
        domain: 'some-random-string-that-should-work'
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
      domain: exchange.variables.domain
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

describe.skip('exchange w/ OID4VP presentation + templated VPR', () => {
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
            "verifiablePresentationRequest": verifiablePresentationRequest
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
            acceptedMethods: [{method: 'key'}]
          },
          domain: baseUrl
        }
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
