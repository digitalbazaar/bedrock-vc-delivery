/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  evaluateTemplate,
  getWorkflowIssuerInstances,
  getZcapClient
} from './helpers.js';
import {createPresentation} from '@digitalbazaar/vc';

export async function issue({
  workflow, exchange, format = 'application/vc'
} = {}) {
  // use any templates from workflow and variables from exchange to produce
  // credentials to be issued; issue via the configured issuer instance
  const verifiableCredential = [];
  const {credentialTemplates = []} = workflow;
  if(!credentialTemplates || credentialTemplates.length === 0) {
    // nothing to issue
    return {response: {}};
  }

  // evaluate template
  const issueRequests = await Promise.all(credentialTemplates.map(
    typedTemplate => evaluateTemplate({workflow, exchange, typedTemplate})));
  // issue all VCs
  const vcs = await _issue({workflow, issueRequests, format});
  verifiableCredential.push(...vcs);

  // generate VP to return VCs
  const verifiablePresentation = createPresentation();
  // FIXME: add any encrypted VCs to VP

  // add any issued VCs to VP
  if(verifiableCredential.length > 0) {
    verifiablePresentation.verifiableCredential = verifiableCredential;
  }
  return {response: {verifiablePresentation}, format};
}

async function _issue({workflow, issueRequests, format} = {}) {
  // create zcap client for issuing VCs
  const {zcapClient, zcaps} = await getZcapClient({workflow});

  // get the zcap to use for the issue requests
  const capability = _getIssueZcap({workflow, zcaps, format});

  // specify URL to `/credentials/issue` to handle case that capability
  // is not specific to it
  let url = capability.invocationTarget;
  if(!capability.invocationTarget.endsWith('/credentials/issue')) {
    url += capability.invocationTarget.endsWith('/credentials') ?
      '/issue' : '/credentials/issue';
  }

  const issuedVCs = [];

  // issue VCs in parallel
  await Promise.all(issueRequests.map(async issueRequest => {
    /* Note: Issue request formats can be any one of these:

    1. `{credential, options?}`
    2. `credential`

    Normalize issue requests that use the full VC API issue request and those
    that return only the `credential` param directly. */
    const json = issueRequest.credential ?
      issueRequest : {credential: issueRequest};
    const {
      data: {verifiableCredential}
    } = await zcapClient.write({url, capability, json});
    issuedVCs.push(verifiableCredential);
  }));

  return issuedVCs;
}

function _getIssueZcap({workflow, zcaps, format}) {
  const issuerInstances = getWorkflowIssuerInstances({workflow});
  const {zcapReferenceIds: {issue: issueRefId}} = issuerInstances.find(
    ({supportedFormats}) => supportedFormats.includes(format));
  return zcaps[issueRefId];
}
