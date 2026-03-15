/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {
  create as createAuthorizationRequest,
  removeClientIdPrefix
} from './authorizationRequest.js';
import {
  evaluateExchangeStep,
  resolveVariableName,
  setVariable
} from '../helpers.js';
import {getClientBaseUrl, getClientProfile} from './clientProfiles.js';
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
    // get supported protocol URL parameters
    const {name, scheme, version} = _getProtocolUrlParameters({clientProfile});

    // generate default OID4VP protocol URL
    const clientBaseUrl = getClientBaseUrl({
      workflow, exchange, clientProfileId
    });
    const {
      authorizationRequest
    } = await _getOrCreateStepAuthorizationRequest({
      workflow, exchange, clientProfileId, clientProfile, step
    });
    const {client_id, request_uri_method} = authorizationRequest;
    const searchParams = new URLSearchParams({
      client_id,
      request_uri: `${clientBaseUrl}/authorization/request`
    });
    if(request_uri_method && version !== 'OID4VP-draft18') {
      searchParams.set('request_uri_method', request_uri_method);
    }
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

  // process exchange and produce result
  let parseResponseResult;
  const result = {};
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    async prepareStep({exchange, step}) {
      const {authorizationRequest} = await getStepAuthorizationRequest({
        workflow, exchange, step, clientProfileId
      });
      result.authorizationRequest = authorizationRequest;

      // ensure authz response can be parsed
      parseResponseResult = await parseAuthorizationResponse({
        req, exchange: exchangeRecord.exchange, clientProfileId,
        authorizationRequest
      });

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

      const {presentation: receivedPresentation} = parseResponseResult;
      return {receivedPresentation};
    },
    inputRequired({step}) {
      // indicate input always required to avoid automatically advancing
      // to issuance, but clear `step.verifiablePresentationRequest`
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

      const {envelope} = parseResponseResult;
      if(envelope?.mediaType === 'application/mdl-vp-token') {
        // generate `handover` for mDL verification
        let handover;

        // common `handover` parameters:
        const origin = authorizationRequest?.expected_origins?.[0] ??
          new URL(authorizationRequest.response_uri).origin;
        const nonce = authorizationRequest.nonce;

        // `direct_post.jwt` => ISO18013-7 Annex B
        // FIXME: same response mode is also used for OID4VP 1.0 with
        // `OpenID4VPHandover` for non-Annex-B; this is not yet supported
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-invocation-via-redirects
        const {responseMode} = parseResponseResult;
        if(responseMode === 'direct_post.jwt') {
          handover = {
            type: 'AnnexBHandover',
            // per ISO 18013-7 B the `mdocGeneratedNonce` is base64url-encoded
            // and put into the `apu` protected header parameter, so parse that
            // here and convert it to a UTF-8 string instead
            mdocGeneratedNonce: Buffer
              .from(parseResponseResult.protectedHeader?.apu ?? '', 'base64url')
              .toString('utf8'),
            clientId: authorizationRequest.client_id,
            responseUri: authorizationRequest.response_uri,
            verifierGeneratedNonce: nonce
          };
        } else if(responseMode === 'dc_api') {
          // `dc_api` => ISO18013-7 Annex C
          handover = {
            type: 'dcapi',
            origin,
            nonce,
            recipientPublicJwk: parseResponseResult.recipientPublicJwk
          };
        } else if(responseMode === 'dc_api.jwt') {
          // `dc_api.jwt` => ISO18013-7 Annex D
          handover = {
            type: 'OpenID4VPDCAPIHandover',
            origin,
            nonce,
            jwkThumbprint: parseResponseResult.recipientPublicJwkThumbprint
          };
        }

        verifyPresentationOptions.mdl = {
          ...verifyPresentationOptions.mdl,
          // send encoded mDL `sessionTranscript`
          sessionTranscript: Buffer
            .from(await oid4vp.mdl.encodeSessionTranscript({handover}))
            .toString('base64url')
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
      const {presentationSubmission} = parseResponseResult;
      exchange.variables.results[exchange.step] = {
        ...exchange.variables.results[exchange.step],
        openId: {
          clientProfileId,
          authorizationRequest,
          presentationSubmission
        }
      };
      if(parseResponseResult.envelope) {
        // include enveloped VP in step result
        exchange.variables.results[exchange.step]
          .envelopedPresentation = presentation;
      }

      return verifyResult;
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

function _getProtocolUrlParameters({clientProfile}) {
  const protocolUrlParameters = {
    name: 'OID4VP',
    scheme: 'openid4vp',
    version: undefined,
    ...clientProfile.protocolUrlParameters
  };
  if(protocolUrlParameters.version === undefined) {
    protocolUrlParameters.version =
      protocolUrlParameters.scheme === 'mdoc-openid4vp' ?
        'OID4VP-draft18' : 'OID4VP-1.0';
  }
  return protocolUrlParameters;
}

async function _getOrCreateStepAuthorizationRequest({
  workflow, exchange, clientProfileId, clientProfile, step
}) {
  let authorizationRequest;

  // get authorization request
  authorizationRequest = clientProfile.authorizationRequest;
  if(authorizationRequest) {
    authorizationRequest = _normalizeAuthorizationRequest({
      authorizationRequest, exchange, clientProfile
    });
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
    authorizationRequest = _normalizeAuthorizationRequest({
      authorizationRequest, exchange, clientProfile
    });
    return {authorizationRequest, exchangeChanged: false};
  }

  // create authz request
  const {verifiablePresentationRequest} = step;
  const result = await createAuthorizationRequest({
    workflow, exchange,
    clientProfile, clientProfileId,
    verifiablePresentationRequest
  });
  authorizationRequest = _normalizeAuthorizationRequest({
    authorizationRequest: result.authorizationRequest, exchange, clientProfile
  });

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

function _normalizeAuthorizationRequest({
  authorizationRequest, exchange, clientProfile
}) {
  const {
    client_id, client_id_scheme, request_uri_method, state
  } = authorizationRequest;
  authorizationRequest = {...authorizationRequest};

  // get any explicit version to be used with client profile
  const {version} = _getProtocolUrlParameters({clientProfile});

  // if `version` is OID4VP draft 18, remove any `client_id_scheme` prefix
  // from the `client_id`; otherwise add it
  if(version === 'OID4VP-draft18') {
    authorizationRequest.client_id = removeClientIdPrefix({
      clientId: client_id
    });
    return authorizationRequest;
  }

  // version is OID4VP 1.0+ or that + compatibility w/Draft18...
  if(client_id_scheme && client_id && !client_id.startsWith(client_id_scheme)) {
    // note: for `redirect_uri` `client_id_scheme`, it is ok to always include
    // `redirect_uri:` prefix in the client ID, even for versions that support
    // Draft 18 compatibility along with other versions, as the client ID
    // should be treated as opaque when using `response_mode=direct*` and
    // omitting the `redirect_uri` parameter; which is the only supported
    // configuration in this implementation for Draft 18 clients
    authorizationRequest.client_id = `${client_id_scheme}:${client_id}`;
  }

  // OID4VP 1.0+ requires `state` to be included for authz requests that do
  // not require "holder binding", but always including it does not cause any
  // known issues, so just include `state` using `referenceId` (if set) or
  // `localExchangeId`
  if(!state && oid4vp.authzRequest.usesClientIdScheme({
    authorizationRequest, scheme: 'redirect_uri'
  })) {
    authorizationRequest.state = exchange.referenceId ?? exchange.id;
  }

  // default to `request_uri_method=post` in OID4VP 1.0+
  if(!request_uri_method) {
    authorizationRequest.request_uri_method = 'post';
  }

  return authorizationRequest;
}

function _throwUnsupportedProtocol() {
  throw new BedrockError('OID4VP is not supported by this exchange.', {
    name: 'NotSupportedError',
    details: {httpStatusCode: 400, public: true}
  });
}
