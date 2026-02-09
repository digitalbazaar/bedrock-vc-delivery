/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from './storage/exchanges.js';
import {
  buildPresentationFromResults,
  buildVerifyPresentationResults,
  emitExchangeUpdated,
  evaluateExchangeStep,
  generateRandom, validateVerifiablePresentation
} from './helpers.js';
import {getIssueRequestsParams, issue} from './issue.js';
import {createPresentation} from '@digitalbazaar/vc';
import {logger} from './logger.js';

const {util: {BedrockError}} = bedrock;

// 15 minute default TTL for exchanges
const DEFAULT_TTL = 1000 * 60 * 60 * 15;

export class ExchangeProcessor {
  /**
   * Creates an `ExchangeProcessor`.
   *
   * @param {object} options - The options to use.
   * @param {object} options.workflow - The workflow.
   * @param {object} options.exchangeRecord - The exchange record.
   * @param {Function} options.inputRequired - The `inputRequired` handler.
   *
   * @returns {ExchangeProcessor} An `ExchangeProcessor` instance.
   */
  constructor({workflow, exchangeRecord, inputRequired} = {}) {
    this.workflow = workflow;
    this.exchangeRecord = exchangeRecord;
    this.inputRequired = inputRequired;
  }

  /**
   * FIXME: `response` or `result`?
   * Processes the exchange until either a response is generated or input is
   * required from the exchange client to continue.
   *
   * @param {object} options - The options to use.
   * @param {object} [options.receivedPresentation] - A verifiable
   *   presentation received from the exchange client in the most recent
   *   protocol message of choice.
   *
   * @returns {Promise<object>} An object with processing information.
   */
  async process({receivedPresentation} = {}) {
    // FIXME: add a note that not every step produces a response, and some
    // steps produce only a partial response that will be sent during the
    // next step
    // FIXME: note that a partial response should NOT be saved by an
    // implementation to allow continuation in the event of a dropped
    // connection, with a preference for the client to have to start a whole
    // new exchange as this might otherwise be indistinguishable from a replay

    const {workflow, exchangeRecord, inputRequired} = this;
    const {exchange, meta} = exchangeRecord;
    let step;

    // 1. If `exchange.state` is `complete` or `invalid`, throw a
    // `NotAllowedError`.
    // note: this will not be saved as a "lastError" in this implementation
    if(exchange.state === 'complete' || exchange.state === 'invalid') {
      throw new BedrockError(`Exchange is ${exchange.state}`, {
        name: 'NotAllowedError',
        details: {httpStatusCode: 403, public: true}
      });
    }

    try {
      // 2. If `exchange.state` is `pending`, set it to `active`.
      if(exchange.state === 'pending') {
        exchange.state = 'active';
      }

      // 3. Initialize `response` to `null`.
      let response = null;

      // 4. Process exchange step(s) until a response is generated, input
      // from the exchange client is required, or the exchange times out:
      const signal = _createTimeoutSignal({exchange, meta});
      while(true) {
        if(signal.aborted()) {
          throw new BedrockError('Exchange has expired.', {
            name: 'DataError',
            details: {httpStatusCode: 500, public: true}
          });
        }

        // 4.1. Get the current step (evaluating a step template as needed).
        const step = await _getStep({workflow, exchange});

        // 4.2. Set `isInputRequired` to the result of calling
        // `inputRequired({step, receivedPresentation})`.
        // FIXME: verify and validate `receivedPresentation` within
        // `inputRequired` or can that be done here?
        const isInputRequired = this.inputRequired({
          step, receivedPresentation
        });

        // 4.3. If `isInputRequired` is true:
        if(isInputRequired) {
          // 4.3.1. If `response` is `null`, set it to an empty object.
          if(!response) {
            response = {};
          }

          // 4.3.2. Set `response.verifiablePresentationRequest` to
          // a copy of `step.verifiablePresentationRequest`.
          response.verifiablePresentationRequest =
            step.verifiablePresentationRequest;

          /*
          - inputRequired(step, protocol):
            a. if protocol == vcapi: return step.vpr && !req.vpr
            b. if protocol == oid4vp: return true
            c. if protocol == oid4vci: return step.vpr &&
              !exchange.results[step].oid4vp
          */
          // 4.3.3. Return `response`.
          return response;
        }

        // 4.4. Set `issueToClient` to `true` if `step.issueRequests` includes
        // any issuer requests for VCs that are to be sent to the client
        // (`issueRequest.result` is NOT set), otherwise set it to `false`.
        const issueRequestsParams = getIssueRequestsParams({
          workflow, exchange, step
        });
        const issueToClient = issueRequestsParams.some(p => !p.result);

        // 4.5. If `step.verifiablePresentation` is set or `issueToClient` is
        // `true`:
        if(step.verifiablePresentation || issueToClient) {
          // 4.5.1. If `response` is not `null` then return `response`:
          if(!response) {
            return response;
          }

          // 4.5.2. Set `response` to an empty object.
          response = {};

          // 4.5.3. If `step.verifiablePresentation` is set, set
          // `response.verifiablePresentation` to a copy of it, otherwise
          // set `response.verifiablePresentation` to a new, empty,
          // Verifiable Presentation (using VCDM 2.0 by default, but a custom
          // configuration could specify another version).
          response.verifiablePresentation =
            structuredClone(step.verifiablePresentation) ??
            createPresentation();
        }

        // 4.6. Perform every issue request (optionally in parallel), returning
        // an error response to the client if any fails (note: implementations
        // can optionally implement failure recovery or retry issue requests at
        // their own discretion):
        // 4.6.1. For each issue request where `result` is set to an exchange
        // variable path or name, save the issued credential in the referenced
        // exchange variable.
        // 4.6.2. For each issue request where `result` is not specified, save
        // the issued credential in `response.verifiablePresentation`, i.e.,
        // for a VCDM presentation, append the issued credential to
        // `response.verifiablePresentation.verifiableCredential`.
        const {exchangeChanged} = await issue({
          workflow, exchange, step, issueRequestsParams,
          verifiablePresentation: response?.verifiablePresentation
        });
        // FIXME: use `exchangeChanged`?

        // 4.7. If either `step.redirectUrl` or `step.nextStep` is set:
        if(step.redirectUrl || step.nextStep) {
          // 4.7.1. If `response` is `null`, set it to an empty object.
          if(!response) {
            response = {};
          }
          // 4.7.2. If `step.redirectUrl` is set then set
          // `response.redirectUrl` to `step.redirectUrl`.
          if(step.redirectUrl) {
            response.redirectUrl = step.redirectUrl;
          }
          // 4.7.3. If `step.nextStep` is set then set
          // `response.verifiablePresentationRequest` to an empty object
          // (to signal that the exchange has not terminated) and set
          // `exchange.step` to `step.nextStep`.
          if(step.nextStep) {
            response.verifiablePresentationRequest = {};
            exchange.step = step.nextStep;
          }
        }

        // 4.8. If `step.nextStep` is not set, set `exchange.state` to
        // `complete`.
        if(step.nextStep) {
          exchange.state = 'complete';
        }

        // FIXME: write step results to exchange variables

        // 4.9. Save the exchange.
        await _updateExchange({workflow, exchange, meta, step});
      }
    } catch(e) {
      if(e.name === 'InvalidStateError') {
        throw e;
      }
      // write last error if exchange hasn't been frequently updated
      const {id: workflowId} = workflow;
      const copy = {...exchange};
      copy.sequence++;
      copy.lastError = e;
      await exchanges.setLastError({
        workflowId, exchange: copy, lastUpdated: meta.updated
      }).catch(error => logger.error(
        'Could not set last exchange error: ' + error.message, {error}));
      await emitExchangeUpdated({workflow, exchange, step});
      throw e;
    }
  }
}

async function _getStep({workflow, exchange}) {
  const currentStep = exchange.step;

  if(!currentStep) {
    // return default empty step
    return {};
  }

  const step = await evaluateExchangeStep({
    workflow, exchange, stepName: currentStep
  });

  // if next step is the same as the current step, throw an error
  if(step.nextStep === currentStep) {
    throw new BedrockError('Cyclical step detected.', {
      name: 'DataError',
      details: {httpStatusCode: 500, public: true}
    });
  }

  // if `step.nextStep` and `step.redirectUrl` and are both set, throw an error
  if(step.nextStep && step.redirectUrl) {
    throw new BedrockError(
      'Only the last step of a workflow can use "redirectUrl".', {
        name: 'DataError',
        details: {httpStatusCode: 500, public: true}
      });
  }

  return step;
}

function _createTimeoutSignal({exchange, meta}) {
  const expires = exchange.expires !== undefined ?
    new Date(exchange.expires).getTime() :
    new Date(meta.created + DEFAULT_TTL).getTime();
  const timeout = Math.max(expires - Date.now(), 0);
  const signal = AbortSignal.timeout(timeout);
  return signal;
}

async function _updateExchange({workflow, exchange, meta, step}) {
  try {
    exchange.sequence++;
    if(exchange.state === 'complete') {
      await exchanges.complete({workflowId: workflow.id, exchange});
    } else {
      await exchanges.update({workflowId: workflow.id, exchange});
    }
    meta.updated = Date.now();
    await emitExchangeUpdated({workflow, exchange, step});
  } catch(e) {
    exchange.sequence--;
    throw e;
  }
}
