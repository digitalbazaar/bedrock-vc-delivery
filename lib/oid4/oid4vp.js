/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  evaluateExchangeStep,
  resolveVariableName,
  setVariable
} from '../helpers.js';
import {getClientBaseUrl, getClientProfile} from './clientProfiles.js';
import {create as createAuthorizationRequest} from './authorizationRequest.js';
import {verify as defaultVerify} from '../verify.js';
import {ExchangeProcessor} from '../ExchangeProcessor.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {parse as parseAuthorizationResponse} from './authorizationResponse.js';

const {util: {BedrockError}} = bedrock;

export {encode as encodeAuthorizationRequest} from './authorizationRequest.js';

export async function getAuthorizationRequest({req, clientProfileId}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();

  // process exchange and capture values to return
  const result = {};
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    async prepareStep({exchange, step}) {
      const {
        clientProfile, authorizationRequest
      } = await getStepAuthorizationRequest({
        workflow, exchange, step, clientProfileId
      });

      // save values to return
      result.clientProfile = clientProfile;
      result.authorizationRequest = authorizationRequest;
      result.exchange = exchange;
      result.step = step;
    },
    inputRequired() {
      // input always required (authz response required)
      return true;
    }
  });
  await exchangeProcessor.process();

  return result;
}

export async function getStepAuthorizationRequest({
  workflow, exchange, step, clientProfileId
}) {
  // step must have `openId` to perform OID4VP
  if(!step.openId) {
    _throwUnsupportedProtocol();
  }
  // deny retrieval of authorization request if an authorization response
  // has already been accepted for this step
  if(exchange.variables.results[exchange.step]?.verifiablePresentation) {
    throw new BedrockError('This OID4VP exchange is already in progress.', {
      name: 'NotAllowedError',
      details: {httpStatusCode: 403, public: true}
    });
  }

  // get OID4VP client profile
  const clientProfile = getClientProfile({step, clientProfileId});

  // generate authorization request
  const {authorizationRequest} = await _getOrCreateStepAuthorizationRequest({
    workflow, exchange, clientProfileId, clientProfile, step
  });

  return {clientProfile, authorizationRequest};
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
    } = await _getOrCreateStepAuthorizationRequest({
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
    _getOrCreateStepAuthorizationRequest({
      workflow, exchange, clientProfileId, clientProfile, step: initialStep
    })));
}

export async function processAuthorizationResponse({req, clientProfileId}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();

  // ensure authz response can be parsed
  const {
    presentation, envelope, presentationSubmission,
    responseMode, protectedHeader,
    recipientPublicJwk, recipientPublicJwkThumbprint
  } = await parseAuthorizationResponse({
    req, exchange: exchangeRecord.exchange, clientProfileId
  });

  // process exchange and produce result
  const result = {};
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    async prepareStep({exchange, step}) {
      const {authorizationRequest} = await getStepAuthorizationRequest({
        workflow, exchange, step, clientProfileId
      });
      result.authorizationRequest = authorizationRequest;

      // ensure response mode matches
      if(responseMode !== authorizationRequest.response_mode) {
        throw new BedrockError(
          `The used response mode ("${responseMode}") does not match the ` +
          `expected response mode ("${authorizationRequest.response_mode}".`, {
            name: 'ConstraintError',
            details: {httpStatusCode: 400, public: true}
          });
      }

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
    },
    inputRequired({step}) {
      // indicate input always required to avoid automatically advancing
      // to the next step, but clear `step.verifiablePresentationRequest`
      // to avoid overwriting previous value
      delete step.verifiablePresentationRequest;
      return true;
    },
    async verify({
      workflow, exchange,
      verifyPresentationOptions,
      verifyPresentationResultSchema,
      presentation,
      allowUnprotectedPresentation,
      expectedChallenge,
      expectedDomain
    }) {
      const {authorizationRequest} = result;
      verifyPresentationOptions.challenge = authorizationRequest.nonce;
      verifyPresentationOptions.domain = authorizationRequest.response_uri;

      // FIXME: OID4VP 1.0+ does not have a presentation submission
      // handle mDL submission
      if(oid4vp.authzResponse.submitsFormat({
        presentationSubmission, format: 'mso_mdoc'
      })) {
        // generate `handover` for mDL verification
        let handover;

        // `direct_post.jwt` => ISO18013-7 Annex B
        // FIXME: same response mode is also used for OID4VP 1.0
        // `OpenID4VPHandover` where `presentationSubmission` will be absent
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-invocation-via-redirects
        if(responseMode === 'direct_post.jwt') {
          handover = {
            type: 'AnnexBHandover',
            // per ISO 18013-7 B the `mdocGeneratedNonce` is base64url-encoded
            // and put into the `apu` protected header parameter -- and the
            // VC API `mdl.sessionTranscript` option expects the
            // `mdocGeneratedNonce` to be base64url-encoded, so we can pass
            // it straight through
            mdocGeneratedNonce: protectedHeader.apu,
            clientId: authorizationRequest.client_id
          };
        } else if(responseMode === 'dc_api') {
          // `dc_api` => ISO18013-7 Annex C
          handover = {
            type: 'dcapi',
            recipientPublicJwk
          };
        } else if(responseMode === 'dc_api.jwt') {
          // `dc_api.jwt` => ISO18013-7 Annex D
          handover = {
            type: 'OpenID4VPDCAPIHandover',
            jwtThumbprint: recipientPublicJwkThumbprint
          };
        }

        verifyPresentationOptions.mdl = {
          ...verifyPresentationOptions.mdl,
          // `domain` and `challenge` options will be automatically used to
          // populate `handover` options as needed so do not send here to avoid
          // redundancy
          handover,
          // for backwards compatibility only, send `handover` as
          // `sessionTranscript` as well
          sessionTranscript: handover
        };
      }

      // verify presentation
      const verifyResult = await defaultVerify({
        workflow,
        verifyPresentationOptions,
        verifyPresentationResultSchema,
        presentation,
        allowUnprotectedPresentation,
        expectedChallenge,
        expectedDomain
      });

      // save OID4VP results in exchange
      exchange.variables.results[exchange.step] = {
        ...exchange.variables.results[exchange.step],
        openId: {
          clientProfileId,
          authorizationRequest,
          presentationSubmission
        }
      };
      if(envelope) {
        // include enveloped VP in step result
        exchange.variables.results[exchange.step]
          .envelopedPresentation = presentation;
      }

      return verifyResult;
    }
  });
  await exchangeProcessor.process({receivedPresentation: presentation});

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

async function _getOrCreateStepAuthorizationRequest({
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
