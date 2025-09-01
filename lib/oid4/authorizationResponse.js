/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
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
    schema: presentationSubmissionSchema
  });
});

export async function parse({req, exchange, clientProfileId} = {}) {
  try {
    const {body} = req;
    const {
      responseMode, parsed, protectedHeader
    } = await oid4vp.verifier.parseAuthorizationResponse({
      body,
      getDecryptParameters() {
        return _getDecryptParameters({exchange, clientProfileId});
      }
    });

    // validate parsed presentation submission
    const {presentationSubmission} = parsed;
    _validate(VALIDATORS.presentationSubmission, presentationSubmission);

    // obtain `presentation` and optional `envelope` from parsed `vpToken`
    const {vpToken} = parsed;
    let presentation;
    let envelope;

    if(oid4vp.authzResponse.submitsFormat({
      presentationSubmission, format: 'mso_mdoc'
    })) {
      // `vp_token` is declared to be a base64url-encoded mDL device response
      presentation = {
        '@context': VC_CONTEXT_2,
        id: `data:application/mdl-vp-token,${vpToken}`,
        type: 'EnvelopedVerifiablePresentation'
      };
    } else if(typeof vpToken === 'string') {
      // FIXME: remove unenveloping here and delegate it to VC API verifier;
      // FIXME: check if envelope matches submission once verified
      const {
        envelope: raw, presentation: contents, format
      } = await unenvelopePresentation({
        envelopedPresentation: vpToken,
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
      // simplest case: `vpToken` is a VP; validate it
      presentation = vpToken;
      _validate(VALIDATORS.presentation, presentation);
      // FIXME: validate VP against presentation submission
    }

    return {
      responseMode,
      presentationSubmission,
      presentation,
      envelope,
      protectedHeader
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
