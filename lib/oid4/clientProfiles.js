/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const {util: {BedrockError}} = bedrock;

export function getClientBaseUrl({workflow, exchange, clientProfileId}) {
  const openIdBaseUrl = `${workflow.id}/exchanges/${exchange.id}/openid`;
  return openIdBaseUrl + (clientProfileId !== undefined ?
    `/clients/${clientProfileId}` : '/client');
}

export function getClientProfile({step, clientProfileId}) {
  const {openId: {clientProfiles}} = step;

  let clientProfile;
  if(clientProfileId !== undefined) {
    if(clientProfiles) {
      clientProfile = clientProfiles[clientProfileId];
    }
  } else if(!clientProfiles) {
    // legacy step without any client profiles
    clientProfile = step.openId;
  }

  if(!clientProfile) {
    throw new BedrockError(
      'The selected OID4VP profile is not supported by this exchange.', {
        name: 'NotSupportedError',
        details: {httpStatusCode: 400, public: true}
      });
  }

  return clientProfile;
}
