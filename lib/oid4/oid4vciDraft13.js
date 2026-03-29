/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {deepEqual} from '../helpers.js';

const {util: {BedrockError}} = bedrock;

export function createSupportedCredentialConfigurations({
  exchange, issuerInstances
} = {}) {
  // get legacy `expectedCredentialRequests`
  const {
    openId: {expectedCredentialRequests}
  } = exchange;

  // build legacy supported credential configurations...
  const supported = new Map();

  // get supported formats from issuer instances
  const supportedFormats = new Set();
  issuerInstances.forEach(instance => instance.supportedFormats.forEach(
    supportedFormats.add, supportedFormats));

  // for every expected credential request and supported format, generate a
  // supported credential configuration
  for(const credentialRequest of expectedCredentialRequests) {
    const configurations = _createCredentialConfigurations({
      credentialRequest, supportedFormats
    });
    for(const {id, configuration} of configurations) {
      supported.set(id, configuration);
    }
  }

  return Object.fromEntries(supported.entries());
}

export function normalizeCredentialRequestsToVersion1({
  credentialRequests, supportedCredentialConfigurations
}) {
  // normalize credential requests to use `type` instead of `types`; this is to
  // allow for OID4VCI draft implementers that followed the non-normative
  // examples
  credentialRequests = _normalizeCredentialDefinitionTypes({
    credentialRequests
  });

  // match draft 13 requests against credential configurations
  return _matchCredentialRequests({
    credentialRequests, supportedCredentialConfigurations
  });
}

function _createCredentialConfigurationId({
  format, credential_definition
}) {
  let types = (credential_definition.type ?? credential_definition.types);
  if(types.length > 1) {
    types = types.filter(t => t !== 'VerifiableCredential');
  }
  return types.join('_') + '_' + format;
}

function _matchCredentialRequest(expected, cr) {
  const {credential_definition: {'@context': c1, type: t1}} = expected;
  const {credential_definition: {'@context': c2, type: t2}} = cr;
  // contexts must match exactly but types can have different order
  return (c1.length === c2.length && t1.length === t2.length &&
    deepEqual(c1, c2) && t1.every(t => t2.some(x => t === x)));
}

function _matchCredentialRequests({
  credentialRequests, supportedCredentialConfigurations
}) {
  // ensure that every credential request is for the same format
  /* credential requests look like:
  {
    format: 'ldp_vc',
    credential_definition: { '@context': [Array], type: [Array] }
  }
  */
  let sharedFormat;
  if(!credentialRequests.every(({format}) => {
    if(sharedFormat === undefined) {
      sharedFormat = format;
    }
    return sharedFormat === format;
  })) {
    throw new BedrockError(
      'Credential requests in a batch must all use the same format.', {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true}
      });
  }

  // ensure every credential request matches a supported configuration
  const entries = Object.entries(supportedCredentialConfigurations);
  return credentialRequests.map(cr => {
    for(const [credential_configuration_id, configuration] of entries) {
      if(_matchCredentialRequest(configuration, cr)) {
        const newRequest = {
          type: 'openid_credential',
          credential_configuration_id
        };
        // only proof type supported for draft 13 is `jwt` per JSON schema that
        // has already run
        if(cr.proof) {
          newRequest.proofs = {
            jwt: [cr.proof.jwt]
          };
        }
        return newRequest;
      }
    }
    throw new BedrockError(
      'Unexpected credential request.', {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true}
      });
  });
}

function _createCredentialConfigurations({
  credentialRequest, supportedFormats
}) {
  const configurations = [];

  let {format: formats = supportedFormats} = credentialRequest;
  if(!Array.isArray(formats)) {
    formats = [formats];
  }

  for(const format of formats) {
    const {credential_definition} = credentialRequest;
    const id = _createCredentialConfigurationId({
      format, credential_definition
    });
    const configuration = {format, credential_definition};
    // FIXME: if `jwtDidProofRequest` exists in (any) step in the exchange,
    // then must include:
    /*
    "proof_types_supported": {
      "jwt": {
        "proof_signing_alg_values_supported": [
          "ES256"
        ]
      }
    }
    */
    configurations.push({id, configuration});
  }

  return configurations;
}

function _normalizeCredentialDefinitionTypes({credentialRequests}) {
  // normalize credential requests to use `type` instead of `types`
  return credentialRequests.map(cr => {
    if(!cr?.credential_definition?.types) {
      return cr;
    }
    cr = {...cr};
    if(!cr.credential_definition.type) {
      cr.credential_definition.type = cr.credential_definition.types;
    }
    delete cr.credential_definition.types;
    return cr;
  });
}
