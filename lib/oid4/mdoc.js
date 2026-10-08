/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc.
 */
import {CoseKey, IsoMdocDcApi} from '@owf/mdoc';
import {getRequestSigningParameters} from './requestSigning.js';
import {selectJwk} from '@digitalbazaar/oid4-client';

const TEXT_ENCODER = new TextEncoder();

export async function createDcApiRequest({
  workflow, clientProfile, authorizationRequest
} = {}) {
  return _createAnnexCDcApiRequest({
    workflow, clientProfile, authorizationRequest
  });
}

async function _createAnnexCDcApiRequest({
  workflow, clientProfile, authorizationRequest
}) {
  // get recipient public key from authz request
  const keys = authorizationRequest.client_metadata.jwks?.keys ?? [];
  // these parameters are only ones supported Annex C for encryption key pair
  const recipientPublicJwk = selectJwk({
    keys, alg: 'ECDH-ES', kty: 'EC', crv: 'P-256'
  });
  // const recipientPublicKey = CoseKey.fromJwk(recipientPublicJwk);
  // only the key material (no `kid`/`alg`), so `EncryptionInfo` matches what
  // oid4-client rebuilds for the `SessionTranscript`
  const {kty, crv, x, y} = recipientPublicJwk;
  const recipientPublicKey = CoseKey.fromJwk({kty, crv, x, y});

  // get signing params
  const {signer} = await getRequestSigningParameters({
    workflow, clientProfile
  });

  // get `x5c` to include in certificate chain
  const {
    authorizationRequestSigningParameters: {x5c} = {},
  } = clientProfile;
  const certificateChain = x5c.map(b64 => Buffer.from(b64, 'base64'));

  // create Annex C DC API mdoc device request
  const {dcql_query: dcqlQuery} = authorizationRequest;
  const {request} = await IsoMdocDcApi.createRequest({
    version: '1.1',
    nonce: TEXT_ENCODER.encode(authorizationRequest.nonce),
    docRequests: _createDocRequests({dcqlQuery}),
    recipientPublicKey,
    readerAuth: {
      signingKey: CoseKey.fromJwk({
        kid: signer.id,
        alg: 'ES256',
        kty: 'EC',
        crv: 'P-256'
      }),
      certificateChain,
      origin: authorizationRequest.expected_origins[0]
    }
  }, _createMdocContext({signer}));

  return {
    meta: {authorizationRequest},
    request: {
      protocol: 'org-iso-mdoc',
      data: request
    }
  };
}

function _createDocRequests({dcqlQuery} = {}) {
  // process all `mso_mdoc` queries as a separate doc request
  const credentials = dcqlQuery?.credentials
    ?.filter(c => c?.format === 'mso_mdoc') ?? [];
  return credentials.map(c => {
    const docType = c.meta?.doctype_value;
    const namespaces = new Map();
    const claims = c.claims ?? [];
    for(const claim of claims) {
      const path = claim.path;
      if(!(Array.isArray(path) && path.length >= 2)) {
        continue;
      }
      const [namespace, field] = path;
      let fields = namespaces.get(namespace);
      if(!fields) {
        namespaces.set(namespace, fields = new Map());
      }
      fields.set(field, true);
    }
    return {docType, namespaces};
  });
}

function _createMdocContext({signer}) {
  const crypto = globalThis.crypto;
  return {
    crypto: {
      async digest({digestAlgorithm, bytes}) {
        const digest = await crypto.subtle.digest(digestAlgorithm, bytes);
        return new Uint8Array(digest);
      },
      random(length) {
        return crypto.getRandomValues(new Uint8Array(length));
      }
    },
    cose: {
      sign1: {
        async sign({toBeSigned}) {
          return signer.sign({data: toBeSigned});
        }
      }
    }
  };
}
