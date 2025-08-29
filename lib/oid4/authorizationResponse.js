/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {importJWK, jwtDecrypt} from 'jose';
import {oid4vp, selectJwk} from '@digitalbazaar/oid4-client';
import {
  presentationSubmission as presentationSubmissionSchema,
  verifiablePresentation as verifiablePresentationSchema
} from '../../schemas/bedrock-vc-workflow.js';
import {compile} from '@bedrock/validation';
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
    const {responseMode, parsed, protectedHeader} = await _parseBody({
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

function _assertSupportedResponseMode({
  responseMode, supportedResponseModes
}) {
  if(!supportedResponseModes.has(responseMode)) {
    const error = new Error(`Unsupported response mode "${responseMode}".`);
    error.name = 'NotSupportedError';
    throw error;
  }
}

async function _decrypt({jwt, getDecryptParameters}) {
  if(typeof getDecryptParameters !== 'function') {
    throw new TypeError(
      '"getDecryptParameters" is required for "direct_post.jwt" ' +
      'response mode.');
  }

  const params = await getDecryptParameters({jwt});
  const {keys} = params;
  let {getKey} = params;
  if(!getKey) {
    // note: `jose` lib's JWK key set feature cannot be used and passed to
    // `jwtDecrypt()` as the second parameter because the expected `alg`
    // "ECDH-ES" is not a unsupported algorithm for selecting a key from a set
    getKey = protectedHeader => {
      if(protectedHeader.alg !== 'ECDH-ES') {
        const error = new Error(
          `Unsupported algorithm "${protectedHeader.alg}"; ` +
          'algorithm must be "ECDH-ES".');
        error.name = 'NotSupportedError';
        error.details = {httpStatusCode: 400, public: true};
        throw error;
      }
      const jwk = selectJwk({keys, kid: protectedHeader.kid});
      return importJWK(jwk, 'ECDH-ES');
    };
  }

  return jwtDecrypt(jwt, getKey, {
    // only supported algorithms at this time:
    contentEncryptionAlgorithms: ['A256GCM'],
    keyManagementAlgorithms: ['ECDH-ES']
  });
}

function _getDecryptParameters({exchange, clientProfileId}) {
  // get private key agreement keys in JWT format
  const {keyAgreementKeyPairs} = exchange.secrets?.oid4vp?.clientProfiles
    ?.[clientProfileId ?? 'default'] ?? {};
  const keys = keyAgreementKeyPairs.map(({privateKeyJwk}) => privateKeyJwk);
  return {keys};
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

async function _parseBody({
  body = {},
  supportedResponseModes = ['direct_post.jwt', 'direct_post'],
  getDecryptParameters
}) {
  let responseMode;
  const parsed = {};
  let payload;
  let protectedHeader;

  supportedResponseModes = new Set(supportedResponseModes);

  if(body.response) {
    // `req.body.response` is present which must contain an encrypted JWT
    responseMode = 'direct_post.jwt';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    const jwt = body.response;
    // FIXME: get decrypt parameters from exchange+clientProfileId
    ({
      payload,
      protectedHeader
    } = await _decrypt({jwt, getDecryptParameters}));
    parsed.presentationSubmission = payload.presentation_submission;
  } else {
    responseMode = 'direct_post';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    payload = body;
    parsed.presentationSubmission = _jsonParse(
      payload.presentation_submission, 'presentation_submission');
  }

  // `vp_token` is either:
  // 1. a JSON object (a VP)
  // 2. a JSON array (of something)
  // 3. a JSON string (a quoted JWT: "<JWT>")
  // 4. a JWT
  // 5. a base64url-encoded mDL device response
  // 6. unknown
  const {vp_token} = payload;
  if(typeof vp_token === 'string' &&
    (vp_token.startsWith('{') || vp_token.startsWith('[') ||
    vp_token.startsWith('"'))) {
    parsed.vpToken = _jsonParse(vp_token, 'vp_token');
  } else {
    parsed.vpToken = vp_token;
  }

  return {responseMode, parsed, payload, protectedHeader};
}

function _validate(validator, data) {
  const result = validator(data);
  if(!result.valid) {
    throw result.error;
  }
}
