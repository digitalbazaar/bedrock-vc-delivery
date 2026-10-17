/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {importJWK, jwtDecrypt} from 'jose';
import {selectJwk} from '@digitalbazaar/oid4-client';

const {util: {BedrockError}} = bedrock;

export async function decryptJwt({exchange, jwt} = {}) {
  // get private key agreement keys in JWK format
  const {keyAgreementKeyPairs} = exchange.secrets ?? {};
  const keys = keyAgreementKeyPairs.map(({privateKeyJwk}) => privateKeyJwk);

  let recipientPublicJwk;
  // note: `jose` lib's JWK key set feature cannot be used and passed to
  // `jwtDecrypt()` as the second parameter because the expected `alg`
  // "ECDH-ES" is not a unsupported algorithm for selecting a key from a set
  const getKey = protectedHeader => {
    if(protectedHeader.alg !== 'ECDH-ES') {
      throw new BedrockError(
        `Unsupported algorithm "${protectedHeader.alg}"; ` +
        'algorithm must be "ECDH-ES".', {
          name: 'NotSupportedError',
          details: {httpStatusCode: 400, public: true}
        });
    }
    const {d, ...rest} = selectJwk({keys, kid: protectedHeader.kid});
    const recipientSecretJwk = {...rest, d};
    recipientPublicJwk = {alg: 'ECDH-ES', use: 'enc', ...rest};
    return importJWK(recipientSecretJwk, 'ECDH-ES');
  };

  try {
    const {payload, protectedHeader} = await jwtDecrypt(jwt, getKey, {
      // only supported algorithms at this time:
      contentEncryptionAlgorithms: ['A256GCM', 'A128GCM'],
      keyManagementAlgorithms: ['ECDH-ES']
    });
    return {payload, protectedHeader, recipientPublicJwk};
  } catch(cause) {
    throw new BedrockError('Decryption failed.', {
      name: 'DataError',
      details: {httpStatusCode: 400, public: true}
    });
  }
}

export function isEncryptedJwt({jwt} = {}) {
  const parts = jwt.split('.');
  return parts.length === 5;
}
