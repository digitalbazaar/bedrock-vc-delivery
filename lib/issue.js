/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
// FIXME: upgrade to eddsa-2022
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
// FIXME: remove `generateRandom`
import {generateRandom} from './helpers.js';
import {httpsAgent} from '@bedrock/https-agent';
import jsonata from 'jsonata';
import {serviceAgents} from '@bedrock/service-agent';
import {ZcapClient} from '@digitalbazaar/ezcap';

const {config} = bedrock;

export async function issue({exchanger, exchange} = {}) {
  // use any templates from exchanger and variables from exchange to produce
  // credentials to be issued; issue via the configured issuer instance
  const verifiableCredential = [];
  const {credentialTemplates = []} = exchanger;
  if(credentialTemplates) {
    const {variables = {}} = exchange;
    // run jsonata compiler; only `jsonata` template type is supported and this
    // was validated when the exchanger was created
    const credentials = credentialTemplates.map(
      ({template: t}) => jsonata(t).evaluate(variables));
    // FIXME: do not overwrite credential IDs; these will be variables in the
    // exchange and will have already been set
    for(const c of credentials) {
      c.id = `urn:uuid:${await generateRandom()}`;
    }

    // issue all VCs
    const vcs = await _issue({exchanger, credentials});
    console.log('vcs', vcs);
    verifiableCredential.push(...vcs);
  }

  // generate VP to return VCs
  const verifiablePresentation = {
    // FIXME: add fields
  };
  // FIXME: add any encrypted VCs to VP

  // add any issued VCs to VP
  if(verifiableCredential.length > 0) {
    verifiablePresentation.verifiableCredential = verifiableCredential
  }
  return {verifiablePresentation};
}

async function _issue({exchanger, credentials} = {}) {
  // FIXME: do not overwrite dates; these will be variables in the exchange
  // and will have already been set
  const now = new Date();
  credentials = credentials.map(credential => {
    credential.issuanceDate = now.toISOString().replace(/\.[0-9]{3}Z/, 'Z');
    return credential;
  });

  // get service agent for communicating with the issuer instance
  const {serviceAgent} = await serviceAgents.get(
    {serviceType: 'vc-exchanger'});
  const {capabilityAgent, zcaps} = await serviceAgents.getEphemeralAgent(
    {config: exchanger, serviceAgent});

  // create zcap client for issuing VCs
  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityAgent.getSigner(),
    SuiteClass: Ed25519Signature2020
  });

  // issue VCs in parallel
  const capability = zcaps.issue;
  const results = await Promise.all(credentials.map(
    credential => zcapClient.write({capability, json: {credential}})));

  // parse VCs from results
  const verifiableCredentials = results.map(
    ({data: {verifiableCredential}}) => verifiableCredential);
  return verifiableCredentials;
}
