/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';

describe('exchange `/request` w/ VC-API', () => {
  let capabilityAgent;
  beforeEach(async () => {
    ({capabilityAgent} = await helpers.provisionDependencies());
  });

  // creates a workflow with a single step and an exchange for it, and
  // returns the response to `GET <exchange>/request`
  async function getRequest({step}) {
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, steps: {start: step}, initialStep: 'start'
    });
    const workflowId = workflowConfig.id;
    const workflowRootZcap =
      `urn:zcap:root:${encodeURIComponent(workflowId)}`;
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap,
      exchange: {ttl: 60 * 15, variables: {}}
    });
    return httpClient.get(`${exchangeId}/request`, {agent});
  }

  it('returns the step\'s verifiable presentation request', async () => {
    const query = {
      type: 'DIDAuthentication',
      acceptedMethods: [{method: 'key'}]
    };
    const response = await getRequest({
      step: {verifiablePresentationRequest: {query}}
    });
    should.exist(response.data?.verifiablePresentationRequest);
    response.data.verifiablePresentationRequest.query.should.deep.equal(
      query);
  });

  it('returns an empty verifiable presentation request when the step ' +
    'has none', async () => {
    const response = await getRequest({
      step: {
        verifiablePresentation: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiablePresentation']
        }
      }
    });
    response.data.should.deep.equal({verifiablePresentationRequest: {}});
  });
});
