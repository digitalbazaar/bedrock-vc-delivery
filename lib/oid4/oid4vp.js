/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  buildPresentationFromResults,
  buildVerifyPresentationResults,
  evaluateExchangeStep,
  resolveVariableName,
  setVariable
} from '../helpers.js';
import {getClientBaseUrl, getClientProfile} from './clientProfiles.js';
import {compile} from '@bedrock/validation';
import {create as createAuthorizationRequest} from './authorizationRequest.js';
import {ExchangeProcessor} from '../ExchangeProcessor.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {parse as parseAuthorizationResponse} from './authorizationResponse.js';
import {verify} from '../verify.js';

const {util: {BedrockError}} = bedrock;

export {encode as encodeAuthorizationRequest} from './authorizationRequest.js';

export async function getAuthorizationRequest({req, clientProfileId}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();

  // process exchange and capture values to return
  const result = {};
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    inputRequired() {
      // input always required; generate a VPR
      return true;
    },
    async validateStep({exchange, step}) {
      // step must have `openId` to perform OID4VP
      if(!step.openId) {
        _throwUnsupportedProtocol();
      }
      // deny retrieval of authorization request if an authorization response
      // has already been accepted for this step
      if(exchange.variables.results[exchange.step]?.verifiablePresentation) {
        throw new BedrockError(
          'This OID4VP exchange is already in progress.', {
            name: 'NotAllowedError',
            details: {httpStatusCode: 403, public: true}
          });
      }

      // get OID4VP client profile
      const clientProfile = getClientProfile({step, clientProfileId});

      // generate authorization request
      const {authorizationRequest} = await _getStepAuthorizationRequest({
        workflow, exchange, clientProfileId, clientProfile, step
      });

      // save values to return
      result.clientProfile = clientProfile;
      result.authorizationRequest = authorizationRequest;
      result.exchange = exchange;
      result.step = step;
    }
  });
  await exchangeProcessor.process();

  return result;
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

  // ensure authz response can be parsed
  const {
    presentation, envelope, presentationSubmission,
    responseMode, protectedHeader
  } = await parseAuthorizationResponse({
    req, exchange: exchangeRecord.exchange, clientProfileId
  });

  // process exchange and produce result
  const result = {};
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    inputRequired({step}) {
      // indicate input always required to avoid automatically advancing
      // to the next step, but clear `step.verifiablePresentationRequest`
      // to avoid overwriting previous value
      delete step.verifiablePresentationRequest;
      return true;
    },
    async validateStep({exchange, step}) {
      // step must have `openId` to perform OID4VP
      if(!step.openId) {
        _throwUnsupportedProtocol();
      }

      // get OID4VP client profile
      const clientProfile = getClientProfile({step, clientProfileId});

      // get authorization request
      const {authorizationRequest} = await _getStepAuthorizationRequest({
        workflow, exchange, clientProfileId, clientProfile, step
      });

      // ensure a result for this step has not already been stored
      const currentStep = exchange.step;
      if(exchange.variables?.results?.[currentStep]?.verifiablePresentation) {
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

      // FIXME: add `ExchangeProcessor` hooks to enable reuse of existing
      // validation and verification code therein
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

      // convert the authz request to a VPR to generate verify options
      const {verifiablePresentationRequest} = await oid4vp.toVpr(
        {authorizationRequest});
      const {
        allowUnprotectedPresentation = false,
        verifyPresentationResultSchema
      } = step;
      const verifyPresentationOptions = {...step.verifyPresentationOptions};

      // FIXME: add `ExchangeProcessor` hooks to enable customizing
      // `verifyPresentationOptions`

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

      // verify the received VP
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

      // FIXME: add `ExchangeProcessor` hooks to enable saving `openId`
      // details in `result`

      // store VP results in variables associated with current step
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

      // explicitly set step result
      exchange.variables.results[currentStep] = {
        ...exchange.variables.results[currentStep],
        ...stepResult
      };

      // only mark exchange complete if there is nothing to be issued; this
      // handles same-step OID4VCI+OID4VP case
      const {credentialTemplates = []} = workflow;
      if(credentialTemplates.length === 0) {
        exchange.state = 'complete';
      }

      // include `redirect_uri` if specified in step
      const {redirect_uri} = step.openId;
      if(redirect_uri) {
        result.redirect_uri = redirect_uri;
      }
    }
  });
  await exchangeProcessor.process();

  return result;
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

  // create or get cached authorization request...

  if(authzReqVarName === '/') {
    // overwriting all variables is not permitted
    throw new BedrockError(
      `Invalid authorization request variable name "${authzReqVarName}".`, {
        name: 'NotSupportedError',
        details: {httpStatusCode: 500, public: true}
      });
  }
  authorizationRequest = resolveVariableName({
    variables: exchange.variables, name: authzReqVarName
  });
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
  setVariable({
    variables: exchange.variables,
    name: authzReqVarName,
    value: authorizationRequest
  });

  return {authorizationRequest, exchangeChanged: true};
}

function _throwUnsupportedProtocol() {
  throw new BedrockError('OID4VP is not supported by this exchange.', {
    name: 'NotSupportedError',
    details: {httpStatusCode: 400, public: true}
  });
}
