/*!
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {ExchangeProcessor} from '../ExchangeProcessor.js';

const {util: {BedrockError}} = bedrock;

export async function processInviteResponse({req}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();

  // `inviteResponse` validated via HTTP body JSON schema already
  const {body: inviteResponse} = req;

  // process exchange to completion
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    prepareStep({exchange, step}) {
      // step must have `inviteRequest` to perform protocol
      if(!step.inviteRequest) {
        _throwUnsupportedProtocol();
      }
      // store invite response in variables associated with current step
      exchange.variables.results[exchange.step] = {
        ...exchange.variables.results[exchange.step],
        inviteRequest: {inviteResponse}
      };
    }
  });
  await exchangeProcessor.process();

  const result = {};
  if(inviteResponse.referenceId !== undefined) {
    result.referenceId = inviteResponse.referenceId;
  }
  return result;
}

export function getInviteRequestProtocols({workflow, exchange, step}) {
  // no invite protocols supported
  if(!supportsInviteRequest({workflow, exchange, step})) {
    return {};
  }

  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  return {inviteRequest: `${exchangeId}/invite-request/response`};
}

export async function initExchange({workflow, exchange, initialStep} = {}) {
  if(!supportsInviteRequest({workflow, exchange, step: initialStep})) {
    return;
  }
  // no special validation rules at this time
}

export function supportsInviteRequest({step} = {}) {
  return !!step?.inviteRequest;
}

function _throwUnsupportedProtocol() {
  throw new BedrockError('Invite request is not supported by this exchange.', {
    name: 'NotSupportedError',
    details: {httpStatusCode: 400, public: true}
  });
}
