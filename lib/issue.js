/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {createPresentation} from '@digitalbazaar/vc';
import {getZcapClient} from './helpers.js';
// FIXME: remove `generateRandom`
import {generateRandom} from './helpers.js';
import jsonata from 'jsonata';

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
  const verifiablePresentation = createPresentation();
  // FIXME: add any encrypted VCs to VP

  // add any issued VCs to VP
  if(verifiableCredential.length > 0) {
    verifiablePresentation.verifiableCredential = verifiableCredential
  }
  return {verifiablePresentation};
}

async function _issue({exchanger, credentials} = {}) {
  // create zcap client for issuing VCs
  const {zcapClient, zcaps} = await getZcapClient({exchanger});

  // issue VCs in parallel
  const capability = zcaps.issue;
  // specify URL to `/credentials/issue` to handle case that capability
  // is not specific to it
  let url = capability.invocationTarget;
  if(!capability.invocationTarget.endsWith('/credentials/issue')) {
    if(!capability.invocationTarget.endsWith('/credentials')) {
      url += '/credentials/issue';
    } else {
      url += '/issue';
    }
  }
  const results = await Promise.all(credentials.map(
    credential => zcapClient.write({url, capability, json: {credential}})));

  // parse VCs from results
  const verifiableCredentials = results.map(
    ({data: {verifiableCredential}}) => verifiableCredential);
  return verifiableCredentials;
}
