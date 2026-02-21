/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  evaluateTemplate,
  getTemplateVariables,
  getWorkflowIssuerInstances,
  getZcapClient,
  setVariable
} from './helpers.js';
import {createPresentation} from '@digitalbazaar/vc';

const {util: {BedrockError}} = bedrock;

export async function issue({
  workflow, exchange, step, format = 'application/vc',
  issueRequestsParams,
  verifiablePresentation,
  // FIXME: remove `filter`
  // by default do not issue any VCs that are to be stored in the exchange;
  // (`result` is NOT set)
  filter = params => !params.result
} = {}) {
  // eval all issue requests for current step in exchange
  const issueRequests = await _evalIssueRequests({
    workflow, exchange, step, issueRequestsParams, filter
  });

  // return early if there is no explicit VP in step nor nothing to issue
  if(!step?.verifiablePresentation && issueRequests.length === 0) {
    return {response: {}, exchangeChanged: false};
  }

  // run all issue requests
  const {
    credentials: issuedVcs,
    exchangeChanged
  } = await _issue({workflow, exchange, issueRequests, format});

  if(issuedVcs.length === 0 && !step?.verifiablePresentation) {
    // no issued VCs/no VP to return in response
    return {response: {}, exchangeChanged};
  }

  // generate VP to return VCs; use any explicitly defined VP from the step
  // (which may include out-of-band issued VCs that are to be delivered)
  verifiablePresentation =
    verifiablePresentation ??
    structuredClone(step?.verifiablePresentation) ??
    createPresentation();

  // add issued VCs to VP
  if(issuedVcs.length > 0) {
    let vcs = verifiablePresentation.verifiableCredential;
    if(!vcs) {
      vcs = issuedVcs;
    } else if(Array.isArray(vcs)) {
      vcs = [...vcs, ...issuedVcs];
    } else {
      vcs = [vcs, ...issuedVcs];
    }
    verifiablePresentation.verifiableCredential = vcs;
  }
  return {response: {verifiablePresentation}, format, exchangeChanged};
}

export function getIssueRequestsParams({workflow, exchange, step}) {
  // use any templates from workflow and variables from exchange to produce
  // credentials to be issued; issue via the configured issuer instance
  const {credentialTemplates = []} = workflow;
  if(!(credentialTemplates.length > 0)) {
    // no issue requests params
    return [];
  }

  if(!workflow.steps ||
    (!step.issueRequests && Object.keys(workflow.steps).length === 1)) {
    // backwards-compatibility: deprecated workflows with no step or a single
    // step do not explicitly define `issueRequests` but instead consider each
    // credential template as the `typedTemplate` parameter (and the only
    // parameter) for an issue request
    return credentialTemplates.map(typedTemplate => ({typedTemplate}));
  }

  if(!step.issueRequests) {
    // no issue requests params
    return [];
  }

  // resolve all issue requests params
  const variables = getTemplateVariables({workflow, exchange});
  return step.issueRequests.map(r => {
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
    const params = {
      typedTemplate,
      variables: {
        // always include globals but allow local override
        globals: variables.globals,
        ...vars
      }
    };
    if(r.result) {
      params.result = r.result;
    }
    return params;
  });
}

async function _evalIssueRequests({
  workflow, exchange, step, issueRequestsParams, filter
}) {
  // evaluate all issue requests in parallel
  const results = issueRequestsParams ??
    getIssueRequestsParams({workflow, exchange, step}).filter(filter);
  return Promise.all(results.map(async params => {
    const {typedTemplate, variables} = params;
    return {
      params,
      body: await evaluateTemplate({
        workflow, exchange, typedTemplate, variables
      })
    };
  }));
}

function _getIssueZcap({workflow, zcaps, format}) {
  const issuerInstances = getWorkflowIssuerInstances({workflow});
  const {zcapReferenceIds: {issue: issueRefId}} = issuerInstances.find(
    ({supportedFormats}) => supportedFormats.includes(format));
  return zcaps[issueRefId];
}

async function _issue({workflow, exchange, issueRequests, format} = {}) {
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
  let exchangeChanged = false;
  const results = await Promise.all(issueRequests.map(async issueRequest => {
    const {params, body} = issueRequest;

    /* Note: Issue request body can be any one of these:

    1. `{credential, options?}`
    2. `credential`

    Normalize all issue request bodies to full VC API issue request bodies. */
    const json = !body?.credential ? {credential: body} : body;
    const {
      data: {verifiableCredential}
    } = await zcapClient.write({url, capability, json});

    // if the issue request specifies a location for storing the credential,
    // put it there and return `undefined`; otherwise, return the credential
    if(params.result) {
      exchangeChanged = true;
      setVariable({
        variables: exchange.variables,
        name: params.result,
        value: verifiableCredential
      });
      return;
    }

    return verifiableCredential;
  }));

  // filter out any undefined results, which are for results that were written
  // to exchange variables and are not to be automatically returned in a
  // presentation
  return {credentials: results.filter(vc => vc), exchangeChanged};
}
