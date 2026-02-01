/*!
 * Copyright (c) 2025-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from '../storage/exchanges.js';
import {emitExchangeUpdated, evaluateExchangeStep} from '../helpers.js';
import {logger} from '../logger.js';

const {util: {BedrockError}} = bedrock;

export async function processInviteResponse({req}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  let {meta: {updated: lastUpdated}} = exchangeRecord;
  const {exchange} = exchangeRecord;
  let step;

  try {
    // exchange step required for `inviteRequest`
    const currentStep = exchange.step;
    if(!currentStep) {
      _throwUnsupportedProtocol();
    }

    step = await evaluateExchangeStep({workflow, exchange});

    // step must have `inviteRequest` to perform protocol
    if(!step.inviteRequest) {
      _throwUnsupportedProtocol();
    }

    // exchange must still be pending
    if(exchange.state !== 'pending') {
      throw new BedrockError(
        'This exchange is already in progress.', {
          name: 'NotAllowedError',
          details: {httpStatusCode: 403, public: true}
        });
    }

    // `inviteResponse` validated via HTTP body JSON schema already
    const {body: inviteResponse} = req;

    // store invite response in variables associated with current step
    if(!exchange.variables.results) {
      exchange.variables.results = {};
    }
    const stepResult = {
      inviteRequest: {inviteResponse}
    };
    const prevState = exchange.state;
    exchange.variables.results[currentStep] = stepResult;
    try {
      // mark exchange complete
      exchange.state = 'complete';
      exchange.sequence++;
      await exchanges.complete({workflowId: workflow.id, exchange});
      await emitExchangeUpdated({workflow, exchange, step});
      lastUpdated = Date.now();
    } catch(e) {
      // revert exchange changes as it couldn't be written
      exchange.sequence--;
      exchange.state = prevState;
      delete exchange.variables.results[currentStep];
      throw e;
    }

    const result = {};
    if(inviteResponse.referenceId !== undefined) {
      result.referenceId = inviteResponse.referenceId;
    }
    return result;
  } catch(e) {
    if(e.name === 'InvalidStateError') {
      throw e;
    }
    // write last error if exchange hasn't been frequently updated
    const {id: workflowId} = workflow;
    const copy = {...exchange};
    copy.sequence++;
    copy.lastError = e;
    await exchanges.setLastError({workflowId, exchange: copy, lastUpdated})
      .catch(error => logger.error(
        'Could not set last exchange error: ' + error.message, {error}));
    await emitExchangeUpdated({workflow, exchange, step});
    throw e;
  }
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
