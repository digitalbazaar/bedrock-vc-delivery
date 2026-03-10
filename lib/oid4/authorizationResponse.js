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
import {unenvelopePresentation} from '../helpers.js';

const {util: {BedrockError}} = bedrock;

const VALIDATORS = {
  presentation: null,
  presentationSubmission: null
};

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

bedrock.events.on('bedrock.init', () => {
  // create validators for x-www-form-urlencoded parsed data
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

    // FIXME: OID4VP 1.0+ does not use presentation submission
    // validate parsed presentation submission if given
    const {presentationSubmission} = parsed;
    if(presentationSubmission) {
      _validate(VALIDATORS.presentationSubmission, presentationSubmission);
    }

    // obtain `presentation` and optional `envelope` from parsed `vpToken`
    const {vpToken} = parsed;
    let presentation;
    let envelope;

    if(vpTokenMediaType === 'application/mdl-vp-token') {
      // `vp_token` is expected to be a base64url-encoded mDL device response
      presentation = {
        '@context': VC_CONTEXT_2,
        id: `data:application/mdl-vp-token,${vpToken}`,
        type: 'EnvelopedVerifiablePresentation'
      };
      envelope = {raw: vpToken, contents: vpToken, format: vpTokenMediaType};
    } else if(vpTokenMediaType === 'application/jwt') {
      // FIXME: remove and combine with other media type conditional above

      // FIXME: remove unenveloping here and delegate it to VC API verifier;
      // FIXME: check if envelope matches submission once verified
      const {
        envelope: raw, presentation: contents, format
      } = await unenvelopePresentation({
        envelopedPresentation: vpToken,
        format: vpTokenMediaType
      });
      // FIXME: remove this, it is done elsewhere
      _validate(VALIDATORS.presentation, contents);
      presentation = {
        '@context': VC_CONTEXT_2,
        id: `data:${format},${raw}`,
        type: 'EnvelopedVerifiablePresentation'
      };
      envelope = {raw, contents, format};
    } else {
      // simplest case: `vpToken` is a VP; validate it
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
