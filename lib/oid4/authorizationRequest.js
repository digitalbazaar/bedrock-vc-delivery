/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {exportJWK, generateKeyPair, UnsecuredJWT} from 'jose';
import {oid4vp, signJWT} from '@digitalbazaar/oid4-client';
import {getClientBaseUrl} from './clientProfiles.js';
import {getZcapClient} from '../helpers.js';
import {httpsAgent} from '@bedrock/https-agent';
import {randomUUID} from 'node:crypto';

const {util: {BedrockError}} = bedrock;

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
    require_signed_request_object,
    response_mode, response_uri
  } = clientProfile;
  const clientBaseUrl = getClientBaseUrl({workflow, exchange, clientProfileId});

  // client_id_scheme (draft versions of OID4VP use this param)
  authorizationRequest.client_id_scheme = client_id_scheme ?? 'redirect_uri';

  // presentation_definition
  authorizationRequest.presentation_definition = presentation_definition ??
    authorizationRequest.presentation_definition;

  // require_signed_request_object
  authorizationRequest.require_signed_request_object =
    require_signed_request_object ?? false;

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

  // `x509_san_dns` requires authz request signing and the `direct_post.jwt`
  // response mode when using `direct_post`
  if(oid4vp.authzRequest.usesClientIdScheme({
    authorizationRequest, scheme: 'x509_san_dns'
  })) {
    authorizationRequest.require_signed_request_object = true;
    if(authorizationRequest.response_mode === 'direct_post') {
      authorizationRequest.response_mode += '.jwt';
    }
  }

  // only set default `aud` for signed OID4VP authz requests
  if(authorizationRequest.require_signed_request_object) {
    authorizationRequest.aud = 'https://self-issued.me/v2';
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

export async function encode({
  workflow, clientProfile, authorizationRequest
} = {}) {
  // if required, construct authz request as signed JWT
  if(authorizationRequest.require_signed_request_object) {
    return _createJwt({workflow, clientProfile, authorizationRequest});
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

async function _createJwt({workflow, clientProfile, authorizationRequest}) {
  try {
    // create zcap client
    const {zcapClient, zcaps} = await getZcapClient({workflow});

    // get any `x5c` and the zcap to use to sign the authz request via
    // the client profile
    const {
      x5c,
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

    // create the JWT payload and header to be signed
    const payload = {
      ...authorizationRequest
    };
    const protectedHeader = {typ: 'JWT', alg: 'ES256', x5c};

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
