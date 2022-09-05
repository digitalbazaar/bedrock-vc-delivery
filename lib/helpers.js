/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import * as bedrock from '@bedrock/core';
import {webcrypto} from 'node:crypto';

const {config, util: {BedrockError}} = bedrock;

export function assert128BitId(id) {
  try {
    // verify ID is base58-encoded multibase multicodec encoded 16 bytes
    const buf = base58.decode(id.substr(1));
    // multibase base58 (starts with 'z')
    // 128-bit random number, multicodec encoded
    // 0x00 = identity tag, 0x10 = length (16 bytes) + 16 random bytes
    if(!(id.startsWith('z') &&
      buf.length === 18 && buf[0] === 0x00 && buf[1] === 0x10)) {
      throw new Error('Invalid identifier.');
    }
  } catch(e) {
    throw new BedrockError(
      `Identifier "${id}" must be base58-encoded multibase, ` +
      'multicodec array of 16 random bytes.', {
        name: 'SyntaxError',
        details: {public: true, httpStatusCode: 400}
      });
  }
}

export function getExchangerId({localId} = {}) {
  assert128BitId(localId);
  const {baseUri} = config.server;
  const baseStorageUrl = `${baseUri}${config['vc-delivery'].routes.basePath}`;
  return `${baseStorageUrl}/${localId}`;
}

export function getRoutes() {
  const cfg = config['vc-delivery'];

  const routes = {...cfg.routes};
  routes.exchangers = routes.basePath;
  routes.exchanger = `${routes.exchangers}/:exchangerId`;
  routes.exchanges = `${routes.exchanger}/exchanges`;
  routes.exchange = `${routes.exchanges}/:exchangeId`;

  return routes;
}

export async function generateRandom() {
  // 128-bit random number, multibase encoded
  // 0x00 = identity tag, 0x10 = length (16 bytes)
  const buf = Buffer.concat([
    Buffer.from([0x00, 0x10]),
    webcrypto.getRandomValues(new Uint8Array(16))
  ]);
  // multibase encoding for base58 starts with 'z'
  return `z${base58.encode(buf)}`;
}

export function parseLocalId({id}) {
  // format: <base>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.substr(idx + 1);
  return {
    base: id.substring(0, idx),
    localId: decodeLocalId({localId})
  };
}

export function decodeLocalId({localId}) {
  // convert to `Buffer` for storage savings (`z<base58-encoded ID>`)
  // where the ID is multicodec encoded 16 byte random value
  // 0x00 = identity tag, 0x10 = length (16 bytes) header
  return Buffer.from(base58.decode(localId.slice(1)).slice(2));
}
