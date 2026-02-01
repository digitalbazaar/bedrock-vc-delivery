/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from '../storage/exchanges.js';
import {
  buildPresentationFromResults,
  buildVerifyPresentationResults,
  emitExchangeUpdated,
  evaluateExchangeStep
} from '../helpers.js';
import {getClientBaseUrl, getClientProfile} from './clientProfiles.js';
import {compile} from '@bedrock/validation';
import {create as createAuthorizationRequest} from './authorizationRequest.js';
import {logger} from '../logger.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {parse as parseAuthorizationResponse} from './authorizationResponse.js';
import {verify} from '../verify.js';

const {util: {BedrockError}} = bedrock;

export {encode as encodeAuthorizationRequest} from './authorizationRequest.js';

export async function getAuthorizationRequest({req, clientProfileId}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  let {exchange} = exchangeRecord;
  let step;
  let clientProfile;

  while(true) {
    // exchange step required for OID4VP
    const currentStep = exchange.step;
    if(!currentStep) {
      _throwUnsupportedProtocol();
    }

    step = await evaluateExchangeStep({workflow, exchange});

    // step must have `openId` to perform OID4VP
    if(!step.openId) {
      _throwUnsupportedProtocol();
    }

    // deny retrieval of authorization request if an authorization response
    // has already been accepted for this step
    if(exchange.variables?.results?.[exchange.step]) {
      throw new BedrockError(
        'This OID4VP exchange is already in progress.', {
          name: 'NotAllowedError',
          details: {httpStatusCode: 403, public: true}
        });
    }

    // get OID4VP client profile
    clientProfile = getClientProfile({step, clientProfileId});

    const {
      authorizationRequest,
      exchangeChanged
    } = await _getStepAuthorizationRequest({
      workflow, exchange, clientProfileId, clientProfile, step
    });

    const prevState = exchange.state;
    let updateExchange = exchangeChanged;
    if(exchange.state === 'pending') {
      exchange.state = 'active';
      updateExchange = true;
    }

    if(updateExchange) {
      try {
        exchange.sequence++;
        await exchanges.update({workflowId: workflow.id, exchange});
        await emitExchangeUpdated({workflow, exchange, step});
      } catch(e) {
        exchange.state = prevState;
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

    return {authorizationRequest, exchange, step, clientProfile};
  }
}

export async function getOID4VPProtocols({workflow, exchange, step}) {
  // no OID4VP protocols supported
  if(!await supportsOID4VP({workflow, exchange, step})) {
    return {};
  }

  // OID4VP supported; add protocol URL for each client profile...
  const {openId} = step;
  const clientProfiles = openId.clientProfiles ?
    Object.entries(openId.clientProfiles) : [[undefined, openId]];

  // generate protocol URL for each client profile; if there are any profile
  // name conflicts, the last profile will provide the profile URL for that
  // profile name
  const protocols = {};
  for(const [clientProfileId, clientProfile] of clientProfiles) {
    // currently, only changing `name` and `scheme` are supported
    const {
      protocolUrlParameters: {
        name = 'OID4VP',
        scheme = 'openid4vp'
      } = {}
    } = clientProfile;

    // generate default OID4VP protocol URL
    const clientBaseUrl = getClientBaseUrl({
      workflow, exchange, clientProfileId
    });
    const {
      authorizationRequest: {client_id}
    } = await _getStepAuthorizationRequest({
      workflow, exchange, clientProfileId, clientProfile, step
    });
    const searchParams = new URLSearchParams({
      client_id,
      request_uri: `${clientBaseUrl}/authorization/request`
    });
    protocols[name] = `${scheme}://?${searchParams}`;
  }
  return protocols;
}

export async function initExchange({workflow, exchange, initialStep} = {}) {
  if(!await supportsOID4VP({workflow, exchange, step: initialStep})) {
    return;
  }

  // generate authz request for initial step for each supported client profile
  // to ensure that OID4VP protocols will be available
  const {openId} = initialStep;
  const clientProfiles = openId.clientProfiles ?
    Object.entries(openId.clientProfiles) : [[undefined, openId]];
  await Promise.all(clientProfiles.map(([clientProfileId, clientProfile]) =>
    _getStepAuthorizationRequest({
      workflow, exchange, clientProfileId, clientProfile, step: initialStep
    })));
}

export async function processAuthorizationResponse({req, clientProfileId}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  let {exchange} = exchangeRecord;

  // ensure authz response can be parsed
  const {
    presentation, envelope, presentationSubmission,
    responseMode, protectedHeader
  } = await parseAuthorizationResponse({req, exchange, clientProfileId});

  let {meta: {updated: lastUpdated}} = exchangeRecord;
  let step;
  try {
    // get authorization request and updated exchange associated with exchange
    const arResult = await getAuthorizationRequest({req, clientProfileId});
    const {authorizationRequest} = arResult;
    ({exchange, step} = arResult);

    // ensure a result for this step has not already been stored
    const currentStep = exchange.step;
    if(exchange.variables?.results?.[currentStep]) {
      throw new BedrockError(
        'This OID4VP exchange is already in progress.', {
          name: 'NotAllowedError',
          details: {httpStatusCode: 403, public: true}
        });
    }

    // ensure response mode matches
    if(responseMode !== authorizationRequest.response_mode) {
      throw new BedrockError(
        `The used response mode ("${responseMode}") does not match the ` +
        `expected response mode ("${authorizationRequest.response_mode}".`, {
          name: 'ConstraintError',
          details: {httpStatusCode: 400, public: true}
        });
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
      verifyPresentationResultSchema
    } = step;
    const verifyPresentationOptions = {
      ...step.verifyPresentationOptions
    };

    // if `direct_post.jwt` used w/ mDL presentation, include `mDL` options
    if(responseMode === 'direct_post.jwt' &&
      oid4vp.authzResponse.submitsFormat({
        presentationSubmission, format: 'mso_mdoc'
      })) {
      verifyPresentationOptions.challenge = authorizationRequest.nonce;
      verifyPresentationOptions.domain = authorizationRequest.response_uri;
      verifyPresentationOptions.mdl = {
        ...verifyPresentationOptions.mdl,
        // note: in session transcript:
        // `domain` option above will be used for `responseUri`
        // `challenge` option above will be used for `verifierGeneratedNonce`
        // so do not send here to avoid redundancy
        sessionTranscript: {
          // per ISO 18013-7 the `mdocGeneratedNonce` is base64url-encoded
          // and put into the `apu` protected header parameter -- and the
          // VC API `mdl.sessionTranscript` option expects the
          // `mdocGeneratedNonce` to be base64url-encoded, so we can pass
          // it straight through
          mdocGeneratedNonce: protectedHeader.apu,
          clientId: authorizationRequest.client_id
        }
      };
    }

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
      verifyPresentationResults: buildVerifyPresentationResults({
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
    const prevState = exchange.state;
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
      await emitExchangeUpdated({workflow, exchange, step});
      lastUpdated = Date.now();
    } catch(e) {
      // revert exchange changes as it couldn't be written
      exchange.sequence--;
      exchange.state = prevState;
      delete exchange.variables.results[currentStep];
      throw e;
    }

    const result = {};

    // include `redirect_uri` if specified in step
    const {redirect_uri} = step.openId;
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
    await exchanges.setLastError({workflowId, exchange: copy, lastUpdated})
      .catch(error => logger.error(
        'Could not set last exchange error: ' + error.message, {error}));
    await emitExchangeUpdated({workflow, exchange, step});
    throw e;
  }
}

export async function supportsOID4VP({workflow, exchange, step}) {
  if(!step) {
    if(!exchange.step) {
      return false;
    }
    step = await evaluateExchangeStep({workflow, exchange});
  }
  return step.openId !== undefined;
}

async function _getStepAuthorizationRequest({
  workflow, exchange, clientProfileId, clientProfile, step
}) {
  let authorizationRequest;

  // get authorization request
  authorizationRequest = clientProfile.authorizationRequest;
  if(authorizationRequest) {
    return {authorizationRequest, exchangeChanged: false};
  }

  // create authorization request...
  // get variable name for authorization request
  const authzReqVarName = clientProfile.createAuthorizationRequest;
  if(authzReqVarName === undefined) {
    _throwUnsupportedProtocol();
  }

  // create or get cached authorization request
  authorizationRequest = exchange.variables?.[authzReqVarName];
  if(authorizationRequest) {
    return {authorizationRequest, exchangeChanged: false};
  }

  // create authz request
  const {verifiablePresentationRequest} = step;
  const result = await createAuthorizationRequest({
    workflow, exchange,
    clientProfile, clientProfileId,
    verifiablePresentationRequest
  });
  authorizationRequest = result.authorizationRequest;

  // merge any newly created exchange secrets
  exchange.secrets = {
    ...exchange.secrets,
    oid4vp: {
      ...exchange.secrets?.oid4vp,
      clientProfiles: {
        ...exchange.secrets?.oid4vp?.clientProfiles,
        [clientProfileId ?? 'default']: result.secrets
      }
    }
  };

  // store generated authorization request
  if(!exchange.variables) {
    exchange.variables = {};
  }
  exchange.variables[authzReqVarName] = authorizationRequest;

  return {authorizationRequest, exchangeChanged: true};
}

function _throwUnsupportedProtocol() {
  throw new BedrockError('OID4VP is not supported by this exchange.', {
    name: 'NotSupportedError',
    details: {httpStatusCode: 400, public: true}
  });
}
