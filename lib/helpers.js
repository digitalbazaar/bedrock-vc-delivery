/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {decodeId, generateId} from 'bnid';

const {config} = bedrock;

export function getExchangerId({localId} = {}) {
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
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
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

export function decodeLocalId({localId} = {}) {
  // convert to `Buffer` for database storage savings
  return Buffer.from(decodeId({
    id: localId,
    encoding: 'base58',
    multibase: true,
    multihash: true,
    expectedSize: 16
  }));
}
