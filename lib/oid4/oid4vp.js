/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from '../exchanges.js';
import {
  buildPresentationFromResults, emitExchangeUpdated,
  evaluateTemplate, unenvelopePresentation,
  validateStep
} from '../helpers.js';
import {
  presentationSubmission as presentationSubmissionSchema,
  verifiablePresentation as verifiablePresentationSchema
} from '../../schemas/bedrock-vc-workflow.js';
import {compile} from '@bedrock/validation';
import {logger} from '../logger.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {verify} from '../verify.js';

const {util: {BedrockError}} = bedrock;

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const VALIDATORS = {
  presentation: null,
  presentationSubmission: null
};

bedrock.events.on('bedrock.init', () => {
  // create validators for x-www-form-urlencoded parsed data
  VALIDATORS.presentation = compile({schema: verifiablePresentationSchema()});
  VALIDATORS.presentationSubmission = compile({
    schema: presentationSubmissionSchema
  });
});

export async function getAuthorizationRequest({req}) {
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

    let updateExchange = false;

    if(exchange.state === 'pending') {
      exchange.state = 'active';
      updateExchange = true;
    }

    // get authorization request
    let authorizationRequest = step.openId.authorizationRequest;
    if(!authorizationRequest) {
      // create authorization request...
      // get variable name for authorization request
      const authzReqName = step.openId.createAuthorizationRequest;
      if(authzReqName === undefined) {
        _throwUnsupportedProtocol();
      }

      // create or get cached authorization request
      authorizationRequest = exchange.variables?.[authzReqName];
      if(!authorizationRequest) {
        const {verifiablePresentationRequest} = step;
        authorizationRequest = oid4vp.fromVpr({verifiablePresentationRequest});

        // add / override params from step `openId` information
        const {
          client_id, client_id_scheme,
          client_metadata, client_metadata_uri,
          nonce, response_uri
        } = step.openId || {};
        if(client_id) {
          authorizationRequest.client_id = client_id;
        } else {
          authorizationRequest.client_id =
            `${workflow.id}/exchanges/${exchange.id}` +
            '/openid/client/authorization/response';
        }
        if(client_id_scheme) {
          authorizationRequest.client_id_scheme = client_id_scheme;
        } else if(authorizationRequest.client_id_scheme === undefined) {
          authorizationRequest.client_id_scheme = 'redirect_uri';
        }
        if(client_metadata) {
          authorizationRequest.client_metadata = structuredClone(
            client_metadata);
        } else if(client_metadata_uri) {
          authorizationRequest.client_metadata_uri = client_metadata_uri;
        } else {
          // auto-generate client_metadata
          authorizationRequest.client_metadata = _createClientMetaData();
        }
        if(nonce) {
          authorizationRequest.nonce = nonce;
        } else if(authorizationRequest.nonce === undefined) {
          // if no nonce has been set for the authorization request, use the
          // exchange ID
          authorizationRequest.nonce = exchange.id;
        }
        if(response_uri) {
          authorizationRequest.response_uri = response_uri;
        } else if(authorizationRequest.response_mode === 'direct_post' &&
          authorizationRequest.client_id_scheme === 'redirect_uri') {
          // `authorizationRequest` uses `direct_post` so force client ID to
          // be the exchange response URL per "Note" here:
          // eslint-disable-next-line max-len
          // https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#section-6.2
          authorizationRequest.response_uri = authorizationRequest.client_id;
        }

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

export async function processAuthorizationResponse({req}) {
  const {
    presentation, envelope, presentationSubmission
  } = await _parseAuthorizationResponse({req});

  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  let {exchange} = exchangeRecord;
  let {meta: {updated: lastUpdated}} = exchangeRecord;
  let step;
  try {
    // get authorization request and updated exchange associated with exchange
    const arRequest = await getAuthorizationRequest({req});
    const {authorizationRequest} = arRequest;
    ({exchange, step} = arRequest);

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
    const currentStep = exchange.step;
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

function _createClientMetaData() {
  // return default supported `vp_formats`
  return {
    vp_formats: {
      // support both aliases `jwt_vp` and `jwt_vp_json`
      jwt_vp: {
        alg: ['EdDSA', 'Ed25519', 'ES256', 'ES384']
      },
      jwt_vp_json: {
        alg: ['EdDSA', 'Ed25519', 'ES256', 'ES384']
      },
      di_vp: {
        proof_type: [
          'ecdsa-rdfc-2019',
          'eddsa-rdfc-2022',
          'Ed25519Signature2020'
        ]
      },
      ldp_vp: {
        proof_type: [
          'ecdsa-rdfc-2019',
          'eddsa-rdfc-2022',
          'Ed25519Signature2020'
        ]
      }
    }
  };
}

async function _parseAuthorizationResponse({req}) {
  // get JSON `vp_token` and `presentation_submission`
  const {vp_token, presentation_submission} = req.body;

  // JSON parse and validate `vp_token` and `presentation_submission`
  let presentation = _jsonParse(vp_token, 'vp_token', true);
  const presentationSubmission = _jsonParse(
    presentation_submission, 'presentation_submission');
  _validate(VALIDATORS.presentationSubmission, presentationSubmission);
  let envelope;
  if(typeof presentation === 'string') {
    // handle enveloped presentation
    const {
      envelope: raw, presentation: contents, format
    } = await unenvelopePresentation({
      envelopedPresentation: presentation,
      // FIXME: check `presentationSubmission` for VP format
      format: 'application/jwt'
    });
    _validate(VALIDATORS.presentation, contents);
    presentation = {
      '@context': VC_CONTEXT_2,
      id: `data:${format},${raw}`,
      type: 'EnvelopedVerifiablePresentation'
    };
    envelope = {raw, contents, format};
  } else {
    _validate(VALIDATORS.presentation, presentation);
  }

  return {presentation, envelope, presentationSubmission};
}

function _jsonParse(x, name, allowJWT = false) {
  try {
    return JSON.parse(x);
  } catch(cause) {
    // presume the string is a non-JSON encoded JWT and let subsequent
    // checking handle it (`ey` is base64url-encoded `{`)
    if(allowJWT && x?.startsWith('ey')) {
      return x;
    }
    throw new BedrockError(`Could not parse "${name}".`, {
      name: 'DataError',
      details: {httpStatusCode: 400, public: true},
      cause
    });
  }
}

function _throwUnsupportedProtocol() {
  throw new BedrockError('OID4VP is not supported by this exchange.', {
    name: 'NotSupportedError',
    details: {httpStatusCode: 400, public: true}
  });
}

function _validate(validator, data) {
  const result = validator(data);
  if(!result.valid) {
    throw result.error;
  }
}
