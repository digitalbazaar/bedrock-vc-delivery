/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';

describe('exchange w/ only "inviteRequest"', () => {
  let capabilityAgent;
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    // require semantically-named workflow steps
    const steps = {
      myStep: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "inviteRequest": inviteRequest
          }`
        }
      }
    };
    // set initial step
    const initialStep = 'myStep';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, steps, initialStep, oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass', async () => {
    // create an exchange with appropriate variables for the step template
    const exchange = {
      // expires in 15 minutes
      expires: (new Date(Date.now() + 60 * 15 * 1000))
        .toISOString().replace(/\.\d+Z$/, 'Z'),
      // template variables
      variables: {
        inviteRequest: true
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });

    // confirm `inviteRequest` URL matches the one in `protocols`
    const inviteRequestUrl = `${exchangeId}/invite-request/response`;
    {
      const protocolsUrl = `${exchangeId}/protocols`;
      const response = await httpClient.get(protocolsUrl, {agent});
      should.exist(response);
      should.exist(response.data);
      should.exist(response.data.protocols);
      // should NOT have VC API
      should.not.exist(response.data.protocols.vcapi);
      // should have `inviteRequest` with:
      // `exchangeId` + `/invite-request/response`
      response.data.protocols.inviteRequest.should.equal(inviteRequestUrl);
    }

    // confirm using exchange w/VC API fails
    {
      let err;
      let response;
      try {
        response = await httpClient.post(exchangeId, {agent, json: {}});
      } catch(error) {
        err = error;
      }
      should.not.exist(response);
      should.exist(err);
      err.message.should.include('not supported');
    }

    // post invite response
    const referenceId = crypto.randomUUID();
    const inviteResponse = {
      url: 'https://retailer.example/checkout/baskets/1',
      purpose: 'checkout',
      referenceId
    };
    const response = await httpClient.post(
      inviteRequestUrl, {agent, json: inviteResponse});
    should.exist(response?.data?.referenceId);
    // ensure `referenceId` matches
    response.data.referenceId.should.equal(referenceId);

    // exchange should be complete and contain the `inviteResponse`
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
          exchange?.variables?.results?.myStep?.inviteRequest?.inviteResponse);
        exchange.variables.results.myStep.inviteRequest.inviteResponse
          .should.deep.equal(inviteResponse);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });
});
