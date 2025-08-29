/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {importJWK, jwtDecrypt} from 'jose';
import {
  presentationSubmission as presentationSubmissionSchema,
  verifiablePresentation as verifiablePresentationSchema
} from '../../schemas/bedrock-vc-workflow.js';
import {compile} from '@bedrock/validation';
import {selectJwk} from '@digitalbazaar/oid4-client';
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
    let responseMode;
    let vp_token;
    let presentation_submission;
    let protectedHeader;

    if(req.body?.response) {
      // `req.body.response` is present which must contain an encrypted JWT
      responseMode = 'direct_post.jwt';
      const jwt = req.body.response;
      ({
        payload: {vp_token, presentation_submission},
        protectedHeader
      } = await _decrypt({jwt, exchange, clientProfileId}));
    } else {
      responseMode = 'direct_post';
      ({vp_token, presentation_submission} = req.body);
      // JSON parse `presentation_submission`
      presentation_submission = _jsonParse(
        presentation_submission, 'presentation_submission');
    }

    // validate `presentation_submission`
    _validate(VALIDATORS.presentationSubmission, presentation_submission);

    // parse and validate `vp_token` into a presentation...
    let presentation;
    let envelope;

    // `vp_token` is either:
    // 1. a JSON object (a VP)
    // 2. a JSON string (a quoted JWT: "<JWT>")
    // 3. a JWT
    // 4. a base64url-encoded mDL device response
    // 5. unknown

    // FIXME: make `format` check more robust
    if(presentation_submission?.descriptor_map?.[0]?.format === 'mso_mdoc') {
      // `vp_token` is declared to be a base64url-encoded mDL device response
      presentation = {
        '@context': VC_CONTEXT_2,
        id: `data:application/mdl-vp-token,${vp_token}`,
        type: 'EnvelopedVerifiablePresentation'
      };
    } else {
      // FIXME: check `format`, however, some implementations still present
      // `vp_token` differently for the same `format` value:
      // `vp_token` is either:
      // 1. a JSON object (a VP)
      // 2. a JSON string ("<JWT>")
      // 3. a JWT
      // 4. unknown
      presentation = _jsonParse(vp_token, 'vp_token', true);
      if(typeof presentation === 'string') {
        // FIXME: remove unenveloping here and delegate it to VC API verifier;
        // FIXME: check if envelope matches submission once verified
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
        // simplest case: `vp_token` is a VP; validate it
        _validate(VALIDATORS.presentation, presentation);
        // FIXME: validate VP against presentation submission
      }
    }

    return {
      presentation, envelope,
      presentationSubmission: presentation_submission,
      responseMode,
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

async function _decrypt({jwt, exchange, clientProfileId}) {
  // get private key agreement key
  // note: `jose` lib's JWK key set feature cannot be used and passed to
  // `jwtDecrypt()` as the second parameter because the expected `alg`
  // "ECDH-ES" is not a unsupported algorithm for selecting a key from a set
  const {keyAgreementKeyPairs} = exchange.secrets?.oid4vp?.clientProfiles
    ?.[clientProfileId ?? 'default'] ?? {};
  const keys = keyAgreementKeyPairs.map(({privateKeyJwk}) => privateKeyJwk);
  const getKey = protectedHeader => {
    if(protectedHeader.alg !== 'ECDH-ES') {
      throw new BedrockError(
        `Unsupported algorithm "${protectedHeader.alg}"; ` +
        'algorithm must be "ECDH-ES".', {
          name: 'NotSupportedError',
          details: {httpStatusCode: 400, public: true}
        });
    }
    const jwk = selectJwk({keys, kid: protectedHeader.kid});
    return importJWK(jwk);
  };
  return jwtDecrypt(jwt, getKey, {
    // only supported algorithms at this time:
    contentEncryptionAlgorithms: ['A256GCM'],
    keyManagementAlgorithms: ['ECDH-ES']
  });
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

function _validate(validator, data) {
  const result = validator(data);
  if(!result.valid) {
    throw result.error;
  }
}
