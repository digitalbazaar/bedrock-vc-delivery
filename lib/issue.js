/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  evaluateTemplate,
  getTemplateVariables,
  getWorkflowIssuerInstances,
  getZcapClient
} from './helpers.js';
import {createPresentation} from '@digitalbazaar/vc';

const {util: {BedrockError}} = bedrock;

export async function issue({
  workflow, exchange, step, format = 'application/vc'
} = {}) {
  // get any out-of-band issued VCs that are to be delivered
  const alreadyIssuedVcs = step?.verifiableCredentials ?? [];

  // eval all issue requests for current step in exchange
  const issueRequests = await _evalIssueRequests({workflow, exchange, step});

  // return early if there is nothing to issue or deliver
  if(alreadyIssuedVcs.length === 0 && issueRequests.length === 0) {
    return {response: {}};
  }

  // run all issue requests
  const issuedVcs = await _issue({workflow, issueRequests, format});

  // generate VP to return VCs
  const verifiablePresentation = createPresentation();

  // add VCs to VP
  const vcs = [...alreadyIssuedVcs, ...issuedVcs];
  if(vcs.length > 0) {
    verifiablePresentation.verifiableCredential = vcs;
  }
  return {response: {verifiablePresentation}, format};
}

async function _evalIssueRequests({workflow, exchange, step}) {
  // evaluate all issue requests in parallel
  const requests = await _getIssueRequests({workflow, exchange, step});
  return Promise.all(requests.map(({typedTemplate, variables}) =>
    evaluateTemplate({workflow, exchange, typedTemplate, variables})));
}

async function _getIssueRequests({workflow, exchange, step}) {
  // use any templates from workflow and variables from exchange to produce
  // credentials to be issued; issue via the configured issuer instance
  const {credentialTemplates = []} = workflow;
  if(!(credentialTemplates.length > 0)) {
    // no issue requests
    return [];
  }

  if(!step ||
    (!step.issueRequests && Object.keys(workflow.steps).length === 1)) {
    // backwards-compatibility: deprecated workflows with no step or a single
    // step do not explicitly define `issueRequests` but instead use all
    // templates for issue requests
    return credentialTemplates.map(typedTemplate => ({typedTemplate}));
  }

  // resolve all issue request params in parallel
  const variables = getTemplateVariables({workflow, exchange});
  return Promise.all(step.issueRequests.map(async r => {
    // find the typed template to use
    let typedTemplate;
    if(r.credentialTemplateIndex !== undefined) {
      typedTemplate = credentialTemplates[r.credentialTemplateIndex];
    } else if(r.credentialTemplateId !== undefined) {
      typedTemplate = credentialTemplates.find(
        t => t.id === r.credentialTemplateId);
    }
    if(typedTemplate === undefined) {
      throw new BedrockError(
        'Credential template ' +
        `"${r.credentialTemplateIndex ?? r.credentialTemplateId}" not found.`, {
          name: 'DataError',
          details: {httpStatusCode: 500, public: true}
        });
    }

    // allow different variables to be specified for the typed template
    let vars = variables;
    if(r.variables !== undefined) {
      vars = typeof r.variables === 'string' ?
        variables[r.variables] : r.variables;
      if(!(vars && typeof vars === 'object')) {
        throw new BedrockError(
          `Issue request variables "${r.variables}" not found or invalid.`, {
            name: 'DataError',
            details: {httpStatusCode: 500, public: true}
          });
      }
    }
    return {
      typedTemplate,
      variables: {
        // always include globals but allow local override
        globals: variables.globals,
        ...vars
      }
    };
  }));
}

function _getIssueZcap({workflow, zcaps, format}) {
  const issuerInstances = getWorkflowIssuerInstances({workflow});
  const {zcapReferenceIds: {issue: issueRefId}} = issuerInstances.find(
    ({supportedFormats}) => supportedFormats.includes(format));
  return zcaps[issueRefId];
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

  // issue VCs in parallel
  return Promise.all(issueRequests.map(async issueRequest => {
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
    return verifiableCredential;
  }));
}
