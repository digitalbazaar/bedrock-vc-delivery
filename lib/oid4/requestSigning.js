/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {AsymmetricKey, KmsClient} from '@digitalbazaar/webkms-client';
import {getZcapClient} from '../helpers.js';
import {httpsAgent} from '@bedrock/https-agent';
import {importJWK} from 'jose';

const {util: {BedrockError}} = bedrock;

export async function getRequestSigningParameters({
  workflow, clientProfile
} = {}) {
  try {
    // create zcap client
    const {zcapClient, zcaps} = await getZcapClient({workflow});

    // get any `x5c` and either `privateKeyJwk` or the zcap to use to sign the
    // authz request via the client profile
    const {
      authorizationRequestSigningParameters: {privateKeyJwk} = {},
      zcapReferenceIds: {signAuthorizationRequest: refId} = {}
    } = clientProfile;
    if(privateKeyJwk === undefined && refId === undefined) {
      throw new BedrockError(
        'The OID4VP client profile does not specify the private key or ' +
        'capability in the  workflow configuration to use to sign ' +
        'authorization requests.', {
          name: 'DataError',
          details: {httpStatusCode: 500, public: true}
        });
    }

    // code assumed ES256 (ECDSA P-256 + SHA-256) support only
    const alg = 'ES256';
    let kid;
    let signer;
    if(privateKeyJwk) {
      kid = privateKeyJwk.kid;

      // import `privateKeyJwk`
      const privateKey = await importJWK(privateKeyJwk, alg);

      // create signer API
      const algorithm = {name: 'ECDSA', hash: {name: 'SHA-256'}};
      signer = {
        async sign({data}) {
          return new Uint8Array(
            await crypto.subtle.sign(algorithm, privateKey, data));
        }
      };
    } else {
      const capability = zcaps[refId];
      if(capability === undefined) {
        throw new BedrockError(
          'The capability specified by the OID4VP client profile for signing ' +
          'authorization requests was not found in the workflow ' +
          'configuration.', {
            name: 'DataError',
            details: {httpStatusCode: 500, public: true}
          });
      }

      // create a WebKMS `signer` interface
      const {invocationSigner} = zcapClient;
      const kmsClient = new KmsClient({httpsAgent});
      signer = await AsymmetricKey.fromCapability({
        capability, invocationSigner, kmsClient
      });
      const keyDescription = await signer.getKeyDescription();
      kid = keyDescription.id;
    }

    return {signer, privateKeyJwk, kid, alg};
  } catch(cause) {
    throw new BedrockError(
      `Could not get request signing parameters: ${cause.message}`, {
        name: cause instanceof BedrockError ? cause.name : 'OperationError',
        cause,
        details: {httpStatusCode: 500, public: true}
      });
  }
}
