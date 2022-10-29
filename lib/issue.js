/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const {config} = bedrock;

export async function issue({exchanger, exchange} = {}) {
  // FIXME: use templates from exchanger and variables from exchange
  // to produce VCs to be issued

  // FIXME: run jsonata compiler

  // FIXME: send generated VCs to issuer service

  // FIXME: return verifiable presentation containing VCs
  const verifiablePresentation = {
    // FIXME: add fields
    // FIXME: implement
    verifiableCredential: [{}]
  };
  return {verifiablePresentation};
}
