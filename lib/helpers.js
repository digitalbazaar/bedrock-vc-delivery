/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {decodeId, generateId} from 'bnid';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {httpsAgent} from '@bedrock/https-agent';
import jsonata from 'jsonata';
import {serviceAgents} from '@bedrock/service-agent';
import {ZcapClient} from '@digitalbazaar/ezcap';

const {config} = bedrock;

export async function evaluateTemplate({
  exchanger, exchange, typedTemplate
} = {}) {
  // run jsonata compiler; only `jsonata` template type is supported and this
  // assumes only this template type will be passed in
  const {template} = typedTemplate;
  const {variables = {}} = exchange;
  // always include `globals` as keyword for self-referencing exchange info
  variables.globals = {
    exchanger: {
      id: exchanger.id
    },
    exchange: {
      id: exchange.id
    }
  };
  return jsonata(template).evaluate(variables, variables);
}

export function getExchangerId({routePrefix, localId} = {}) {
  return `${config.server.baseUri}${routePrefix}/${localId}`;
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

export async function getZcapClient({exchanger} = {}) {
  // get service agent for communicating with the issuer instance
  const {pathname} = new URL(exchanger.id);
  // backwards-compatibility: support deprecated `vc-exchanger`
  const serviceType = pathname.startsWith('/workflows/') ?
    'vc-workflow' : 'vc-exchanger';
  const {serviceAgent} = await serviceAgents.get({serviceType});
  const {capabilityAgent, zcaps} = await serviceAgents.getEphemeralAgent(
    {config: exchanger, serviceAgent});

  // create zcap client for issuing VCs
  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityAgent.getSigner(),
    SuiteClass: Ed25519Signature2020
  });

  return {zcapClient, zcaps};
}

export function parseLocalId({id}) {
  // format: <base>/<localId>
  const idx = id.lastIndexOf('/');
  const localId = id.slice(idx + 1);
  return {
    base: id.slice(0, idx),
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
