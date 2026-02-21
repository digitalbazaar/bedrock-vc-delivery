/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as vcjwt from './vcjwt.js';
import {decodeId, generateId} from 'bnid';
import {compile} from '@bedrock/validation';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {httpClient} from '@digitalbazaar/http-client';
import {httpsAgent} from '@bedrock/https-agent';
import jsonata from 'jsonata';
import jsonpointer from 'json-pointer';
import {logger} from './logger.js';
import {serializeError} from 'serialize-error';
import {serviceAgents} from '@bedrock/service-agent';
import {ZcapClient} from '@digitalbazaar/ezcap';

const {config, util: {BedrockError}} = bedrock;

const ALLOWED_ERROR_KEYS = [
  'message', 'name', 'type', 'data', 'errors', 'error', 'details', 'cause',
  'status'
];

const JWT_FORMAT_ALIASES = new Set([
  'application/jwt',
  'application/vc+jwt',
  'application/vp+jwt',
  'jwt_vp',
  'jwt_vp_json',
  'jwt_vc_json-ld',
  'jwt_vc_json'
]);

export function buildPresentationFromResults({
  presentation, verifyResult
}) {
  // build VP w/all envelopes removed (if any)
  const vp = {
    ...(verifyResult?.presentationResult?.presentation ?? presentation)
  };
  let credentials = vp.verifiableCredential;
  const {credentialResults} = verifyResult;
  if(credentials && credentialResults) {
    if(!Array.isArray(credentials)) {
      credentials = [credentials];
    }
    const hasEnvelopedVC = credentials.some(
      vc => vc.type === 'EnvelopedVerifiableCredential');
    if(!hasEnvelopedVC) {
      // no enveloped VCs to update, return early
      return vp;
    }
    // walk credential results and produce unenveloped output
    vp.verifiableCredential = credentialResults.map(r => r.credential);
  }
  return vp;
}

export function buildVerifyPresentationResults({verifyResult}) {
  /*if(verifyResult.results) {
    // VCALM-compliant result already available, use it or a minimized version
    // of it to avoid hitting exchange storage capacity limits
  }*/

  // backwards-compatibility: construct VCALM-compliant result
  return {
    verified: verifyResult.verified,
    results: {
      presentation: {
        verified: verifyResult.presentationResult?.verified,
        proof: verifyResult.presentationResult?.results?.map(r => ({
          verified: r.verified,
          input: r.proof
        })),
      },
      credentials: verifyResult.credentialResults?.map(r => ({
        verified: r.verified,
        results: {
          proof: r.results?.map(r => ({
            verified: r.verified,
            input: r.proof
          })),
          credentialStatus: r.statusResult?.results?.map(r => ({
            verified: r.verified,
            input: r.credentialStatus,
            value: r.status
          }))
        }
      }))
    }
  };
}

export function emitExchangeUpdated({workflow, exchange, step}) {
  if(!step?.callback?.url) {
    // no-op when there is no callback to notify
    return;
  }

  const {url} = step.callback;
  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  return httpClient.post(url, {
    agent: httpsAgent,
    json: {
      event: {
        data: {exchangeId}
      }
    }
  }).catch(
    error => logger.error(
      'Could not send "exchangeUpdated" push notification: ' +
      error.message, {error}));
}

export async function evaluateTemplate({
  workflow, exchange, typedTemplate, variables
} = {}) {
  // run jsonata compiler; only `jsonata` template type is supported and this
  // assumes only this template type will be passed in
  const {template} = typedTemplate;
  variables = variables ?? getTemplateVariables({workflow, exchange});
  return jsonata(template).evaluate(variables, variables);
}

export async function evaluateExchangeStep({
  workflow, exchange, stepName = exchange.step
}) {
  let step = workflow.steps[stepName];
  if(step.stepTemplate) {
    step = await evaluateTemplate({
      workflow, exchange, typedTemplate: step.stepTemplate
    });
  }
  await validateStep({step});
  return step;
}

export function getTemplateVariables({workflow, exchange} = {}) {
  const {variables = {}} = exchange;
  // always include `globals` as keyword for self-referencing exchange info
  variables.globals = {
    workflow: {
      id: workflow.id
    },
    exchange: {
      id: exchange.id
    },
    localExchangeId: exchange.id,
    exchangeId: `${workflow.id}/exchanges/${exchange.id}`,
    // backwards compatibility
    exchanger: {
      id: workflow.id
    }
  };
  return variables;
}

export function getWorkflowId({routePrefix, localId} = {}) {
  return `${config.server.baseUri}${routePrefix}/${localId}`;
}

export async function generateRandom() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}

export function getWorkflowIssuerInstances({workflow} = {}) {
  let {issuerInstances} = workflow;
  if(!issuerInstances && workflow.zcaps.issue) {
    // generate dynamic issuer instance config
    issuerInstances = [{
      supportedFormats: ['application/vc', 'ldp_vc'],
      zcapReferenceIds: {
        issue: 'issue'
      }
    }];
  }
  return issuerInstances;
}

export async function getZcapClient({workflow} = {}) {
  // get service agent for communicating with the issuer instance
  const {pathname} = new URL(workflow.id);
  // backwards-compatibility: support deprecated `vc-exchanger`
  const serviceType = pathname.startsWith('/workflows/') ?
    'vc-workflow' : 'vc-exchanger';
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const {capabilityAgent, zcaps} = await serviceAgents.getEphemeralAgent(
    {config: workflow, serviceAgent});

  // create zcap client for issuing VCs
  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityAgent.getSigner(),
    SuiteClass: Ed25519Signature2020
  });

  return {zcapClient, zcaps};
}

export function parseLocalId({id}) {
  // format: <base>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.slice(idx + 1);
  return {
    base: id.slice(0, idx),
    localId: decodeLocalId({localId})
  };
}

export function decodeLocalId({localId} = {}) {
  // convert to `Buffer` for database storage savings
  return Buffer.from(decodeId({
    id: localId,
    encoding: 'base58',
    multibase: true,
    multihash: true,
    expectedSize: 16
  }));
}

export function deepEqual(obj1, obj2) {
  const isObject1 = obj1 && typeof obj1 === 'object';
  const isObject2 = obj2 && typeof obj2 === 'object';
  if(isObject1 !== isObject2) {
    return false;
  }
  if(!isObject1) {
    return obj1 === obj2;
  }
  const isArray1 = Array.isArray(obj1);
  const isArray2 = Array.isArray(obj2);
  if(isArray1 !== isArray2) {
    return false;
  }
  if(isArray1) {
    if(obj1.length !== obj2.length) {
      return false;
    }
    for(const [i, e] of obj1.entries()) {
      if(!deepEqual(e, obj2[i])) {
        return false;
      }
    }
    return true;
  }
  const keys1 = Object.keys(obj1);
  const keys2 = Object.keys(obj2);
  if(keys1.length !== keys2.length) {
    return false;
  }
  for(const k of keys1) {
    if(!deepEqual(obj1[k], obj2[k])) {
      return false;
    }
  }
  return true;
}

export function createVerifyOptions({
  verifyPresentationOptions,
  expectedChallenge,
  verifiablePresentationRequest,
  presentation,
  domain,
  checks
}) {
  // start with `verifyPresentationOptions`, then overwrite as needed
  const options = {...verifyPresentationOptions};

  // update `checks` with anything additional from `verifyPresentationOptions`
  const checkSet = new Set(checks);
  if(verifyPresentationOptions.checks) {
    Object.entries(verifyPresentationOptions.checks)
      .forEach(([check, enabled]) => enabled && checkSet.add(check));
  }
  options.checks = [...checkSet];

  // update `challenge`
  if(options.challenge === undefined) {
    options.challenge = expectedChallenge ??
      verifiablePresentationRequest?.challenge ??
      presentation?.proof?.challenge;
  }

  // update `domain`
  if(options.domain === undefined) {
    options.domain = domain;
  }

  return options;
}

export function resolvePointer(obj, pointer) {
  if(pointer === '/') {
    return obj;
  }
  try {
    return jsonpointer.get(obj, pointer);
  } catch(e) {
    return undefined;
  }
}

export function resolveVariableName({variables, name} = {}) {
  if(!name.startsWith('/')) {
    return variables[name];
  }
  if(name === '/') {
    return variables;
  }
  try {
    return jsonpointer.get(variables, name);
  } catch(e) {
    return undefined;
  }
}

export function setVariable({variables, name, value} = {}) {
  if(!name.startsWith('/')) {
    variables[name] = value;
    return;
  }
  if(name === '/') {
    throw new BedrockError(
      `Invalid variable name "${name}".`, {
        name: 'NotSupportedError',
        details: {httpStatusCode: 500, public: true}
      });
  }
  jsonpointer.set(variables, name, value);
}

export function stripStacktrace(error) {
  // serialize error and allow-list specific properties
  const serialized = serializeError(error);
  error = {};
  for(const key of ALLOWED_ERROR_KEYS) {
    if(serialized[key] !== undefined) {
      error[key] = serialized[key];
    }
  }
  if(error.errors) {
    error.errors = error.errors.map(stripStacktrace);
  }
  if(Array.isArray(error.details?.errors)) {
    error.details.errors = error.details.errors.map(stripStacktrace);
  }
  if(error.cause) {
    error.cause = stripStacktrace(error.cause);
  }
  return error;
}

export async function unenvelopeCredential({
  envelopedCredential, format
} = {}) {
  const result = _getEnvelope({envelope: envelopedCredential, format});

  // only supported format is VC-JWT at this time
  const credential = vcjwt.decodeVCJWTCredential({jwt: result.envelope});
  return {credential, ...result};
}

export async function unenvelopePresentation({
  envelopedPresentation, format
} = {}) {
  const result = _getEnvelope({envelope: envelopedPresentation, format});

  // only supported format is VC-JWT at this time
  const presentation = vcjwt.decodeVCJWTPresentation({jwt: result.envelope});

  // unenvelope any VCs in the presentation
  let {verifiableCredential = []} = presentation;
  if(!Array.isArray(verifiableCredential)) {
    verifiableCredential = [verifiableCredential];
  }
  if(verifiableCredential.length > 0) {
    presentation.verifiableCredential = await Promise.all(
      verifiableCredential.map(async vc => {
        if(vc?.type !== 'EnvelopedVerifiableCredential') {
          return vc;
        }
        const {credential} = await unenvelopeCredential({
          envelopedCredential: vc
        });
        return credential;
      }));
  }
  return {presentation, ...result};
}

export async function validateStep({step} = {}) {
  // FIXME: use `ajv` and do JSON schema check
  if(Object.keys(step).length === 0) {
    throw new BedrockError('Empty exchange step detected.', {
      name: 'DataError',
      details: {httpStatusCode: 500, public: true}
    });
  }
  if(step.issueRequests !== undefined && !Array.isArray(step.issueRequests)) {
    throw new BedrockError(
      'Invalid "issueRequests" in step.', {
        name: 'DataError',
        details: {httpStatusCode: 500, public: true}
      });
  }
  // use of `jwtDidProofRequest` and `openId` together is prohibited
  const {jwtDidProofRequest, openId} = step;
  if(jwtDidProofRequest && openId) {
    throw new BedrockError(
      'Invalid workflow configuration; only one of ' +
      '"jwtDidProofRequest" and "openId" is permitted in a step.', {
        name: 'DataError',
        details: {httpStatusCode: 500, public: true}
      });
  }
}

function _getEnvelope({envelope, format}) {
  const isString = typeof envelope === 'string';
  if(isString) {
    // supported formats
    if(JWT_FORMAT_ALIASES.has(format)) {
      format = 'application/jwt';
    }
  } else {
    const {id} = envelope;
    if(id?.startsWith('data:application/jwt,')) {
      format = 'application/jwt';
      envelope = id.slice('data:application/jwt,'.length);
    }
  }

  if(format === 'application/jwt' && envelope !== undefined) {
    return {envelope, format};
  }

  throw new BedrockError(
    `Unsupported credential or presentation envelope format "${format}".`, {
      name: 'NotSupportedError',
      details: {httpStatusCode: 400, public: true}
    });
}

export function validateVerifiablePresentation({schema, presentation}) {
  const validate = compile({schema});
  const {valid, error} = validate(presentation);
  if(!valid) {
    throw error;
  }
}
