/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {exportJWK, generateKeyPair, UnsecuredJWT} from 'jose';
import {getClientBaseUrl} from './clientProfiles.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {randomUUID} from 'node:crypto';

export async function create({
  workflow, exchange,
  clientProfile, clientProfileId,
  verifiablePresentationRequest
}) {
  const authorizationRequest = oid4vp.fromVpr({verifiablePresentationRequest});

  // get params from step OID4VP client profile to apply to the AR
  const {
    client_id, client_id_scheme,
    nonce,
    presentation_definition,
    response_mode, response_uri
  } = clientProfile;
  const clientBaseUrl = getClientBaseUrl({workflow, exchange, clientProfileId});

  // client_id_scheme (draft versions of OID4VP use this param)
  authorizationRequest.client_id_scheme = client_id_scheme ?? 'redirect_uri';

  // presentation_definition
  authorizationRequest.presentation_definition = presentation_definition ??
    authorizationRequest.presentation_definition;

  // response_mode
  authorizationRequest.response_mode = response_mode ?? 'direct_post';

  // response_uri
  authorizationRequest.response_uri = response_uri ??
    `${clientBaseUrl}/authorization/response`;

  // client_id (defaults to `response_uri`)
  // FIXME: newer versions of OID4VP require a prefix of `redirect_uri:` for
  // the default case -- which is incompatible with some draft versions
  authorizationRequest.client_id = client_id ??
    authorizationRequest.response_uri;

  // `x509_san_dns` requires authz request signing and therefore requires the
  // `direct_post.jwt` response mode when using `direct_post`
  if(authorizationRequest.response_mode === 'direct_post' &&
    oid4vp.authzRequest.usesClientIdScheme({
      authorizationRequest, scheme: 'x509_san_dns'
    })) {
    authorizationRequest.response_mode += '.jwt';
  }

  // nonce
  if(nonce) {
    authorizationRequest.nonce = nonce;
  } else if(authorizationRequest.nonce === undefined) {
    // if no nonce has been set for the authorization request, use the
    // exchange ID
    authorizationRequest.nonce = exchange.id;
  }

  // client_metadata; create from the `clientProfile` the rest of the AR and
  // generate any necessary secrets for it
  const {client_metadata, secrets} = await _createClientMetaData({
    authorizationRequest, clientProfile
  });
  authorizationRequest.client_metadata = client_metadata;

  return {authorizationRequest, secrets};
}

export async function encode({authorizationRequest} = {}) {
  if(authorizationRequest.require_signed_request_object) {
    // construct authz request as signed JWT
    // FIXME:
    return new UnsecuredJWT(authorizationRequest).encode();
  }

  // construct authz request as unsecured JWT
  return new UnsecuredJWT(authorizationRequest).encode();
}

async function _createClientMetaData({
  authorizationRequest, clientProfile
} = {}) {
  // for storing client profile secrets
  const secrets = {};

  // create base `client_metadata` from client profile override or defaults
  let client_metadata;
  if(clientProfile.client_metadata) {
    client_metadata = structuredClone(clientProfile.client_metadata);
  } else {
    // use default supported `vp_formats`
    const vp_formats = {
      // support both aliases `jwt_vp` and `jwt_vp_json`
      jwt_vp: {
        alg: ['EdDSA', 'Ed25519', 'ES256', 'ES384']
      },
      jwt_vp_json: {
        alg: ['EdDSA', 'Ed25519', 'ES256', 'ES384']
      },
      // support both aliases `di_vp` and `ldp_vp`
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
    };

    // add `mso_mdoc` format based on query
    if(oid4vp.authzRequest.requestsFormat({
      authorizationRequest, format: 'mso_mdoc'
    })) {
      vp_formats.mso_mdoc = {
        alg: ['EdDSA', 'ES256']
      };
    }

    client_metadata = {vp_formats};
  }

  // `x509_san_dns` client ID scheme requires authz request signing;
  // any client ID scheme that requires this
  if(oid4vp.authzRequest.usesClientIdScheme({
    authorizationRequest, scheme: 'x509_san_dns'
  })) {
    client_metadata.require_signed_request_object = true;
  }

  // for response mode `direct_post.jwt`, offer encryption options
  if(authorizationRequest.response_mode === 'direct_post.jwt') {
    // generate ECDH-ES P-256 key
    const kp = await generateKeyPair('ECDH-ES', {
      crv: 'P-256', extractable: true
    });
    const [privateKeyJwk, publicKeyJwk] = await Promise.all([
      exportJWK(kp.privateKey),
      exportJWK(kp.publicKey)
    ]);
    publicKeyJwk.use = 'enc';
    publicKeyJwk.alg = 'ECDH-ES';
    privateKeyJwk.kid = publicKeyJwk.kid = `urn:uuid:${randomUUID()}`;
    secrets.keyAgreementKeyPairs = [{privateKeyJwk, publicKeyJwk}];

    // create public JWK key set
    client_metadata.jwks = {
      keys: [publicKeyJwk]
    };
  }

  return {client_metadata, secrets};
}
