/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {evaluateTemplate, getZcapClient} from './helpers.js';
import {createPresentation} from '@digitalbazaar/vc';

export async function issue({workflow, exchange} = {}) {
  // use any templates from workflow and variables from exchange to produce
  // credentials to be issued; issue via the configured issuer instance
  const verifiableCredential = [];
  const {credentialTemplates = []} = workflow;
  if(!credentialTemplates || credentialTemplates.length === 0) {
    // nothing to issue
    return {response: {}};
  }

  // evaluate template
  const credentialRequests = await Promise.all(credentialTemplates.map(
    typedTemplate => evaluateTemplate({workflow, exchange, typedTemplate})));
  // issue all VCs
  const vcs = await _issue({workflow, credentialRequests});
  verifiableCredential.push(...vcs);

  // generate VP to return VCs
  const verifiablePresentation = createPresentation();
  // FIXME: add any encrypted VCs to VP

  // add any issued VCs to VP
  if(verifiableCredential.length > 0) {
    verifiablePresentation.verifiableCredential = verifiableCredential;
  }
  return {response: {verifiablePresentation}};
}

async function _issue({workflow, /*exchange,*/ credentialRequests} = {}) {
  // create zcap client for issuing VCs
  const {zcapClient, zcaps} = await getZcapClient({workflow});

  // FIXME: if `exchange` specifically indicates the issuer instances to
  // use for particular credential requests, use those instances, otherwise
  // pick the instance according to the first matching supported format
  // for each credential request

  // FIXME: use the first matching issuer instance's `zcapReferenceIds.issue`
  // zcap, otherwise use `zcap.issue`
  const capability = zcaps.issue;
  // FIXME: implement
  // console.log('exchange', exchange);
  // console.log('credentialRequests', credentialRequests);

  // specify URL to `/credentials/issue` to handle case that capability
  // is not specific to it
  let url = capability.invocationTarget;
  if(!capability.invocationTarget.endsWith('/credentials/issue')) {
    url += capability.invocationTarget.endsWith('/credentials') ?
      '/issue' : '/credentials/issue';
  }

  // issue VCs in parallel
  const results = await Promise.all(credentialRequests.map(request => {
    /* Note: Credential request formats can be any one of these:

    1. `{credential, options?}`
    2. `credential`

    Normalize credential requests that use the full VC API issue credential
    request and those that return only the `credential` param directly. */
    const json = request.credential ? request : {credential: request};
    return zcapClient.write({url, capability, json});
  }));

  // parse VCs from results
  const verifiableCredentials = results.map(
    ({data: {verifiableCredential}}) => verifiableCredential);
  return verifiableCredentials;
}
