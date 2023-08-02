/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {createPresentation} from '@digitalbazaar/vc';
import {getZcapClient} from './helpers.js';
import jsonata from 'jsonata';

export async function issue({exchanger, exchange} = {}) {
  // use any templates from exchanger and variables from exchange to produce
  // credentials to be issued; issue via the configured issuer instance
  const verifiableCredential = [];
  const {credentialTemplates = []} = exchanger;
  if(credentialTemplates) {
    const {variables = {}} = exchange;
    // run jsonata compiler; only `jsonata` template type is supported and this
    // was validated when the exchanger was created
    const credentials = await Promise.all(credentialTemplates.map(
      async ({template: t}) => {
        const {vc, ...bindings} = variables;
        return vc ? jsonata(t).evaluate({vc}, bindings) :
          jsonata(t).evaluate(variables);
      }));
    // issue all VCs
    const vcs = await _issue({exchanger, credentials});
    verifiableCredential.push(...vcs);
  }

  // generate VP to return VCs
  const verifiablePresentation = createPresentation();
  // FIXME: add any encrypted VCs to VP

  // add any issued VCs to VP
  if(verifiableCredential.length > 0) {
    verifiablePresentation.verifiableCredential = verifiableCredential;
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
