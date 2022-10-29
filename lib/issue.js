/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import jsonata from 'jsonata';

const {config} = bedrock;

export async function issue({exchanger, exchange} = {}) {
  // FIXME: use templates from exchanger and variables from exchange
  // to produce VCs to be issued

  // run jsonata compiler; only `jsonata` template type is supported and this
  // was validated when the exchanger was created
  const {credentialTemplates = []} = exchanger;
  // FIXME: can an exchanger have no credential templates?
  if(credentialTemplates) {
    const {variables = {}} = exchange;
    const credentials = credentialTemplates.map(
      ({template: t}) => jsonata(t).evaluate(variables));
    console.log('credentials', credentials);
  }

  // FIXME: send generated VCs to issuer service

  // FIXME: return verifiable presentation containing VCs
  const verifiablePresentation = {
    // FIXME: add fields
    // FIXME: implement
    verifiableCredential: [{}]
  };
  return {verifiablePresentation};
}
