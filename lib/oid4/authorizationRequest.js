/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {exportJWK, generateKeyPair} from 'jose';
import {oid4vp, signJWT} from '@digitalbazaar/oid4-client';
import {getClientBaseUrl} from './clientProfiles.js';
import {getZcapClient} from '../helpers.js';
import {httpsAgent} from '@bedrock/https-agent';
import {randomUUID} from 'node:crypto';

const {util: {BedrockError}} = bedrock;

const OID4VP_JWT_TYP = 'oauth-authz-req+jwt';
const TEXT_ENCODER = new TextEncoder();

export async function create({
  workflow, exchange,
  clientProfile, clientProfileId,
  verifiablePresentationRequest
}) {
  const authorizationRequest = verifiablePresentationRequest ?
    oid4vp.fromVpr({verifiablePresentationRequest}) :
    // default authz request
    {response_type: 'vp_token'};

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

  // `x509_san_dns` requires the `direct_post.jwt` response mode when using
  // `direct_post`
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

  // only set default `aud` for signed OID4VP authz requests
  if(client_metadata.require_signed_request_object) {
    authorizationRequest.aud = 'https://self-issued.me/v2';
  }

  return {authorizationRequest, secrets};
}

export async function encode({
  workflow, clientProfile, authorizationRequest
} = {}) {
  // if required, construct authz request as signed JWT
  if(authorizationRequest.client_metadata.require_signed_request_object) {
    return _createJwt({workflow, clientProfile, authorizationRequest});
  }

  // construct authz request as unsecured JWT with `typ` header set
  // to `OID4VP_JWT_TYP` value; note that the `UnsecuredJWT` API from `jose`
  // cannot be used because it does not allow customization of the JWT header
  // which is required to comply with OID4VP 1.0
  const header = Buffer
    .from(JSON.stringify({alg: 'none', typ: OID4VP_JWT_TYP}), 'utf8')
    .toString('base64url');
  const payload = Buffer
    .from(TEXT_ENCODER.encode(JSON.stringify(authorizationRequest)))
    .toString('base64url');
  const jwt = `${header}.${payload}.`;
  return jwt;
}

async function _createClientMetaData({
  authorizationRequest, clientProfile
} = {}) {
  // for storing client profile secrets
  const secrets = {};

  // create base `client_metadata` from client profile if given, falling
  // back to the value in the authz request which might be auto-generated
  const client_metadata = structuredClone(
    clientProfile.client_metadata ??
    authorizationRequest.client_metadata ?? {});

  // ensure `vp_formats` and `vp_formats_supported` exists and track whether it
  // was present or not
  const hasVpFormats = !!client_metadata.vp_formats;
  if(!hasVpFormats) {
    client_metadata.vp_formats = {};
  }

  // add `mso_mdoc` format if requested and not already present
  if(!client_metadata.vp_formats.mso_mdoc &&
    oid4vp.authzRequest.requestsFormat({
      authorizationRequest, format: 'mso_mdoc'
    })) {
    client_metadata.vp_formats.mso_mdoc = {
      alg: ['EdDSA', 'ES256']
    };
  }

  // add `jwt_vp` format if requested and not already present
  if(!client_metadata.vp_formats.jwt_vp &&
    oid4vp.authzRequest.requestsFormat({
      authorizationRequest, format: 'jwt_vp'
    })) {
    // support various aliases for different versions of OID4VP
    client_metadata.vp_formats.jwt_vp =
      client_metadata.vp_formats.jwt_vp_json = {
        alg: ['EdDSA', 'Ed25519', 'ES256', 'ES384']
      };
  }

  // add `ldp_vp` format if requested and not already present or if no other
  // formats are present
  if(!hasVpFormats || (!client_metadata.vp_formats.ldp_vp &&
    oid4vp.authzRequest.requestsFormat({
      authorizationRequest, format: 'ldp_vp'
    }))) {
    // support various aliases for different versions of OID4VP
    client_metadata.vp_formats.di_vp =
      client_metadata.vp_formats.ldp_vp = {
        proof_type: [
          'ecdsa-rdfc-2019',
          'eddsa-rdfc-2022',
          'Ed25519Signature2020'
        ]
      };
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

    // create / prepend to public JWK key set
    client_metadata.jwks = {
      ...client_metadata.jwks,
      keys: [publicKeyJwk].concat(client_metadata.jwks?.keys ?? [])
    };
  }

  return {client_metadata, secrets};
}

async function _createJwt({workflow, clientProfile, authorizationRequest}) {
  try {
    // create zcap client
    const {zcapClient, zcaps} = await getZcapClient({workflow});

    // get any `x5c` and the zcap to use to sign the authz request via
    // the client profile
    const {
      authorizationRequestSigningParameters: {x5c} = {},
      zcapReferenceIds: {signAuthorizationRequest: refId} = {}
    } = clientProfile;
    if(refId === undefined) {
      throw new BedrockError(
        'The OID4VP client profile does not specify which capability in the ' +
        'workflow configuration to use to sign authorization requests.', {
          name: 'DataError',
          details: {httpStatusCode: 500, public: true}
        });
    }
    const capability = zcaps[refId];
    if(capability === undefined) {
      throw new BedrockError(
        'The capability specified by the OID4VP client profile for signing ' +
        'authorization requests was not found in the workflow configuration.', {
          name: 'DataError',
          details: {httpStatusCode: 500, public: true}
        });
    }

    // create a WebKMS `signer` interface
    const {invocationSigner} = zcapClient;
    const kmsClient = new KmsClient({httpsAgent});
    const signer = await AsymmetricKey.fromCapability({
      capability, invocationSigner, kmsClient
    });
    const keyDescription = await signer.getKeyDescription();
    const kid = keyDescription.id;

    // create the JWT payload and header to be signed
    const payload = {
      ...authorizationRequest
    };
    const protectedHeader = {typ: OID4VP_JWT_TYP, alg: 'ES256', kid, x5c};

    // create the JWT
    return signJWT({payload, protectedHeader, signer});
  } catch(cause) {
    throw new BedrockError(
      `Could not sign authorization request: ${cause.message}`, {
        name: cause instanceof BedrockError ? cause.name : 'OperationError',
        cause,
        details: {httpStatusCode: 500, public: true}
      });
  }
}
