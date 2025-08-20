/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from '../exchanges.js';
import {
  buildPresentationFromResults, emitExchangeUpdated,
  evaluateTemplate, validateStep
} from '../helpers.js';
import {getClientBaseUrl, getClientProfile} from './clientProfiles.js';
import {compile} from '@bedrock/validation';
import {create as createAuthorizationRequest} from './authorizationRequest.js';
import {logger} from '../logger.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {parse as parseAuthorizationResponse} from './authorizationResponse.js';
import {verify} from '../verify.js';

const {util: {BedrockError}} = bedrock;

export async function getAuthorizationRequest({req, clientProfileId}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  let {exchange} = exchangeRecord;
  let step;

  while(true) {
    // exchange step required for OID4VP
    const currentStep = exchange.step;
    if(!currentStep) {
      _throwUnsupportedProtocol();
    }

    step = workflow.steps[exchange.step];
    if(step.stepTemplate) {
      // generate step from the template; assume the template type is
      // `jsonata` per the JSON schema
      step = await evaluateTemplate(
        {workflow, exchange, typedTemplate: step.stepTemplate});
    }
    await validateStep({step});

    // step must have `openId` to perform OID4VP
    if(!step.openId) {
      _throwUnsupportedProtocol();
    }

    // get OID4VP client profile
    const clientProfile = getClientProfile({step, clientProfileId});

    let updateExchange = false;
    if(exchange.state === 'pending') {
      exchange.state = 'active';
      updateExchange = true;
    }

    // get authorization request
    let authorizationRequest = clientProfile.authorizationRequest;
    if(!authorizationRequest) {
      // create authorization request...
      // get variable name for authorization request
      const authzReqName = clientProfile.createAuthorizationRequest;
      if(authzReqName === undefined) {
        _throwUnsupportedProtocol();
      }

      // create or get cached authorization request
      authorizationRequest = exchange.variables?.[authzReqName];
      if(!authorizationRequest) {
        const {verifiablePresentationRequest} = step;
        authorizationRequest = createAuthorizationRequest({
          workflow, exchange,
          clientProfile, clientProfileId,
          verifiablePresentationRequest
        });

        // store generated authorization request
        updateExchange = true;
        if(!exchange.variables) {
          exchange.variables = {};
        }
        exchange.variables[authzReqName] = authorizationRequest;
      }
    }

    if(updateExchange) {
      try {
        exchange.sequence++;
        await exchanges.update({workflowId: workflow.id, exchange});
        emitExchangeUpdated({workflow, exchange, step});
      } catch(e) {
        exchange.sequence--;
        if(e.name !== 'InvalidStateError') {
          // unrecoverable error
          throw e;
        }
        // get exchange and loop to try again on `InvalidStateError`
        const record = await exchanges.get(
          {workflowId: workflow.id, id: exchange.id});
        ({exchange} = record);
        continue;
      }
    }

    return {authorizationRequest, exchange, step};
  }
}

export async function getOID4VPProtocols({workflow, exchange}) {
  if(!exchange.step) {
    return {};
  }
  let step = workflow.steps[exchange.step];
  if(step.stepTemplate) {
    step = await evaluateTemplate(
      {workflow, exchange, typedTemplate: step.stepTemplate});
  }
  if(!step.openId) {
    return {};
  }

  // OID4VP supported; add openid4vp URL(s) for each client profile...
  const clientProfiles = step.openId.clientProfiles ?
    Object.entries(step.openId.clientProfiles) :
    [[undefined, step.openId]];

  if(!step.openId.clientProfiles) {
    const clientBaseUrl = getClientBaseUrl({workflow, exchange});

    // no client profiles; return only default protocol URL
    const searchParams = new URLSearchParams({
      client_id: `${clientBaseUrl}/authorization/response`,
      request_uri: `${clientBaseUrl}/authorization/request`
    });
    return {
      OID4VP: `openid4vp://?${searchParams}`
    };
  }

  // generate protocol URL for each client profile; if there are any profile
  // name conflicts, the last profile will provide the profile URL for that
  // profile name
  let protocols = {};
  for(const [clientProfileId, clientProfile] of clientProfiles) {
    const {protocols: clientProtocols} = clientProfile;
    if(clientProtocols) {
      protocols = {
        ...protocols,
        ...clientProtocols
      };
      continue;
    }

    // generate default OID4VP protocol URL
    const clientBaseUrl = getClientBaseUrl({
      workflow, exchange, clientProfileId
    });
    const searchParams = new URLSearchParams({
      // FIXME: get `client_id` from authorization request if possible
      client_id: `${clientBaseUrl}/authorization/response`,
      request_uri: `${clientBaseUrl}/authorization/request`
    });
    protocols.OID4VP = `openid4vp://?${searchParams}`;
  }
  return protocols;
}

export async function processAuthorizationResponse({req, clientProfileId}) {
  // FIXME: pass expected response mode to `parseAuthorizationResponse`
  const {
    presentation, envelope, presentationSubmission
  } = await parseAuthorizationResponse({req});

  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  let {exchange} = exchangeRecord;
  let {meta: {updated: lastUpdated}} = exchangeRecord;
  let step;
  try {
    // get authorization request and updated exchange associated with exchange
    const arRequest = await getAuthorizationRequest({req, clientProfileId});
    const {authorizationRequest} = arRequest;
    ({exchange, step} = arRequest);

    // ensure a different exchange `clientProfile` hasn't already been chosen
    const currentStep = exchange.step;
    {
      const stepResult = exchange.variables?.results?.[currentStep];
      if(stepResult?.openId.clientProfileId &&
        stepResult.openId.clientProfileId !== clientProfileId) {
        throw new BedrockError(
          'This OID4VP exchange is already in progress.', {
            name: 'InvalidStateError',
            details: {httpStatusCode: 409, public: true}
          });
      }
    }

    // FIXME: check the VP against the presentation submission if requested
    // FIXME: check the VP against "trustedIssuer" in VPR, if provided
    const {presentationSchema} = step;
    if(presentationSchema) {
      // if the VP is enveloped, validate the contents of the envelope
      const toValidate = envelope ? envelope.contents : presentation;

      // validate the received VP / envelope contents
      const {jsonSchema: schema} = presentationSchema;
      const validate = compile({schema});
      const {valid, error} = validate(toValidate);
      if(!valid) {
        throw error;
      }
    }

    // verify the received VP
    const {verifiablePresentationRequest} = await oid4vp.toVpr(
      {authorizationRequest});
    const {
      allowUnprotectedPresentation = false,
      verifyPresentationOptions = {},
      verifyPresentationResultSchema
    } = step;
    const verifyResult = await verify({
      workflow,
      verifyPresentationOptions,
      verifyPresentationResultSchema,
      verifiablePresentationRequest,
      presentation,
      allowUnprotectedPresentation,
      expectedChallenge: authorizationRequest.nonce
    });
    const {verificationMethod} = verifyResult;

    // store VP results in variables associated with current step
    if(!exchange.variables.results) {
      exchange.variables.results = {};
    }
    const stepResult = {
      // common use case of DID Authentication; provide `did` for ease
      // of use in template
      did: verificationMethod?.controller || null,
      verificationMethod,
      verifiablePresentation: buildPresentationFromResults({
        presentation,
        verifyResult
      }),
      openId: {
        clientProfileId,
        authorizationRequest,
        presentationSubmission
      }
    };
    if(envelope) {
      // include enveloped VP in step result
      stepResult.envelopedPresentation = presentation;
    }
    exchange.variables.results[currentStep] = stepResult;
    try {
      exchange.sequence++;

      // if there is something to issue, update exchange, do not complete it
      const {credentialTemplates = []} = workflow;
      if(credentialTemplates?.length > 0 &&
        (exchange.state === 'pending' || exchange.state === 'active')) {
        // ensure exchange state is set to `active` (will be rejected as a
        // conflict if the state in database at update time isn't `pending` or
        // `active`)
        exchange.state = 'active';
        await exchanges.update({workflowId: workflow.id, exchange});
      } else {
        // mark exchange complete
        exchange.state = 'complete';
        await exchanges.complete({workflowId: workflow.id, exchange});
      }
      emitExchangeUpdated({workflow, exchange, step});
      lastUpdated = Date.now();
    } catch(e) {
      exchange.sequence--;
      throw e;
    }

    const result = {};

    // include `redirect_uri` if specified in step
    const redirect_uri = step.openId?.redirect_uri;
    if(redirect_uri) {
      result.redirect_uri = redirect_uri;
    }

    return result;
  } catch(e) {
    if(e.name === 'InvalidStateError') {
      throw e;
    }
    // write last error if exchange hasn't been frequently updated
    const {id: workflowId} = workflow;
    const copy = {...exchange};
    copy.sequence++;
    copy.lastError = e;
    exchanges.setLastError({workflowId, exchange: copy, lastUpdated})
      .catch(error => logger.error(
        'Could not set last exchange error: ' + error.message, {error}));
    emitExchangeUpdated({workflow, exchange, step});
    throw e;
  }
}

export async function supportsOID4VP({workflow, exchange}) {
  if(!exchange.step) {
    return false;
  }
  let step = workflow.steps[exchange.step];
  if(step.stepTemplate) {
    step = await evaluateTemplate(
      {workflow, exchange, typedTemplate: step.stepTemplate});
  }
  return step.openId !== undefined;
}

function _throwUnsupportedProtocol() {
  throw new BedrockError('OID4VP is not supported by this exchange.', {
    name: 'NotSupportedError',
    details: {httpStatusCode: 400, public: true}
  });
}
