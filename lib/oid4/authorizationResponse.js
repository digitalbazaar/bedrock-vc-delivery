/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
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

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

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
      vpTokenMediaType
    } = await oid4vp.verifier.parseAuthorizationResponse({
      body,
      getDecryptParameters() {
        return _getDecryptParameters({exchange, clientProfileId});
      },
      authorizationRequest
    });

    // validate parsed presentation submission if given
    const {presentationSubmission} = parsed;
    if(presentationSubmission) {
      _validate(VALIDATORS.presentationSubmission, presentationSubmission);
    }

    // obtain `presentation` and optional `envelope` from parsed `vpToken`
    const {vpToken} = parsed;
    let presentation;
    let envelope;

    if(vpTokenMediaType !== 'application/vp') {
      // `vp_token` contains some enveloped format
      presentation = {
        '@context': VC_CONTEXT_2,
        id: `data:${vpTokenMediaType},${vpToken}`,
        type: 'EnvelopedVerifiablePresentation'
      };
      envelope = {mediaType: vpTokenMediaType};
    } else {
      // simplest case: `vpToken` is a VP; validate it against basic schema
      presentation = vpToken;
      _validate(VALIDATORS.presentation, presentation);
    }

    return {
      responseMode,
      presentationSubmission,
      presentation,
      envelope,
      protectedHeader,
      recipientPublicJwk,
      recipientPublicJwkThumbprint
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

function _getDecryptParameters({exchange, clientProfileId}) {
  // get private key agreement keys in JWT format
  const {keyAgreementKeyPairs} = exchange.secrets?.oid4vp?.clientProfiles
    ?.[clientProfileId ?? 'default'] ?? {};
  const keys = keyAgreementKeyPairs.map(({privateKeyJwk}) => privateKeyJwk);
  return {keys};
}

function _validate(validator, data) {
  const result = validator(data);
  if(!result.valid) {
    throw result.error;
  }
}
