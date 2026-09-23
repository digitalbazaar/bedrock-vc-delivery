/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {
  presentationSubmission as presentationSubmissionSchema,
  verifiablePresentation as verifiablePresentationSchema
} from '../../schemas/bedrock-vc-workflow.js';
import {compile} from '@bedrock/validation';
import {oid4vp} from '@digitalbazaar/oid4-client';

const {util: {BedrockError}} = bedrock;

const VALIDATORS = {
  presentation: null,
  presentationSubmission: null
};

bedrock.events.on('bedrock.init', () => {
  VALIDATORS.presentation = compile({schema: verifiablePresentationSchema()});
  VALIDATORS.presentationSubmission = compile({
    schema: presentationSubmissionSchema()
  });
});

export async function parse({
  req, exchange, clientProfileId, authorizationRequest
} = {}) {
  try {
    const {body} = req;
    const {
      responseMode, parsed, protectedHeader,
      recipientPublicJwk, recipientPublicJwkThumbprint,
      vpTokenMediaType,
      envelope, presentation, mdocOptions
    } = await oid4vp.verifier.parseAuthorizationResponse({
      body,
      getDecryptParameters({mdocOptions} = {}) {
        return _getDecryptParameters({
          exchange, clientProfileId, authorizationRequest, mdocOptions
        });
      },
      authorizationRequest
    });

    // validate parsed presentation submission if given
    const {presentationSubmission} = parsed;
    if(presentationSubmission) {
      _validate(VALIDATORS.presentationSubmission, presentationSubmission);
    }

    // validate `presentation` against basic schema
    if(vpTokenMediaType === 'application/vp') {
      _validate(VALIDATORS.presentation, presentation);
    }

    return {
      responseMode,
      presentationSubmission,
      presentation,
      envelope,
      protectedHeader,
      recipientPublicJwk,
      recipientPublicJwkThumbprint,
      mdocOptions
    };
  } catch(cause) {
    throw new BedrockError(
      `Could not parse authorization response: ${cause.message}`, {
        name: cause.name ?? 'OperationError',
        cause,
        details: {
          httpStatusCode: cause?.details?.httpStatusCode ?? 400,
          public: true
        }
      });
  }
}

function _getDecryptParameters({
  exchange, clientProfileId, authorizationRequest, mdocOptions
}) {
  // get private key agreement keys in JWT format
  const {keyAgreementKeyPairs} = exchange.secrets?.oid4vp?.clientProfiles
    ?.[clientProfileId ?? 'default'] ?? {};
  const keys = keyAgreementKeyPairs.map(({privateKeyJwk}) => privateKeyJwk);

  // include decryption AAD info if `response_mode` calls for it
  let getInfo;
  if(authorizationRequest.response_mode === 'dc_api') {
    // include `recipientPublicJwk` in expected mdoc handover
    getInfo = ({recipientPublicJwk}) => {
      const handover = {
        ...mdocOptions?.expectedHandover,
        recipientPublicJwk
      };
      return oid4vp.mdl.encodeSessionTranscript({handover});
    };
  }

  return {keys, getInfo};
}

function _validate(validator, data) {
  const result = validator(data);
  if(!result.valid) {
    throw result.error;
  }
}
