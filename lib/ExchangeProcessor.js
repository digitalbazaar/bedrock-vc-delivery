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
  validateVerifiablePresentation,
  validateVerifiablePresentationRequest
} from './helpers.js';
import {createChallenge, verify as defaultVerify} from './verify.js';
import {issue as defaultIssue, getIssueRequestsParams} from './issue.js';
import {createPresentation} from '@digitalbazaar/vc';
import {logger} from './logger.js';

const {util: {BedrockError}} = bedrock;

// 15 minute default TTL for exchanges
const DEFAULT_TTL = 1000 * 60 * 60 * 15;
// maximum steps while looping
const MAXIMUM_STEP_COUNT = 100;

export class ExchangeProcessor {
  /**
   * Creates an `ExchangeProcessor`.
   *
   * @param {object} options - The options to use.
   * @param {object} options.workflow - The workflow.
   * @param {object} options.exchangeRecord - The exchange record.
   * @param {Function} [options.prepareStep] - The `prepareStep` handler.
   * @param {Function} [options.inputRequired] - The `inputRequired` handler.
   * @param {Function} [options.issue] - The `issue` handler.
   * @param {Function} [options.verify] - The `verify` handler.
   *
   * @returns {ExchangeProcessor} An `ExchangeProcessor` instance.
   */
  constructor({
    workflow, exchangeRecord, prepareStep, inputRequired,
    issue, verify
  } = {}) {
    this.workflow = workflow;
    this.exchangeRecord = exchangeRecord;
    this.prepareStep = prepareStep?.bind(this);
    this.inputRequired = inputRequired?.bind(this);
    this.issue = issue ?? defaultIssue.bind(this);
    this.verify = verify ?? defaultVerify.bind(this);
  }

  /**
   * Processes the exchange until either a response to be used with the
   * exchange client is generated or input is required from the exchange client
   * to continue.
   *
   * Note: An exchange is an particular running instantation of a workflow. The
   * exchange processor will walkthrough the step(s) of the workflow to
   * produce a respnose that can be used to communicate with the exchange
   * client according to the protocol being used to execute the exchange. Not
   * every step of a workflow produces a response and some steps produce a
   * partial response, whereby the next step adds information to complete
   * the response.
   *
   * It is up to the caller of `process()` to use the response generated to
   * appropriately communicate with the exchange client according to the rules
   * of the operating protocol.
   *
   * Sometimes errors may occur during an exchange. Not every possible error
   * is recoverable. Some information that is generated on a workflow server
   * may not be intended to be seen by a coordinator system that can poll the
   * exchange state and some information may not be able to be regenerated
   * without a new exchange.
   *
   * In rare cases, it is possible that a generated response will not reach the
   * client due to a network connection error that is not perceived by the
   * server. In this case, the expectation is that another exchange will have
   * to be started to attempt the interaction again.
   *
   * @param {object} options - The options to use.
   * @param {object} [options.receivedPresentation] - A verifiable
   *   presentation received from the exchange client in the most recent
   *   protocol message of choice.
   * @param {object} [options.receivedPresentationRequest] - A verifiable
   *   presentation request received from the exchange client in the most
   *   recent protocol message of choice.
   *
   * @returns {Promise<object>} An object with processing information.
   */
  async process({receivedPresentation, receivedPresentationRequest} = {}) {
    const retryState = {};
    while(true) {
      try {
        retryState.canRetry = false;
        const response = await this._tryProcess({
          receivedPresentation, receivedPresentationRequest, retryState
        });
        return response;
      } catch(e) {
        if(e.name === 'InvalidStateError' && retryState.canRetry) {
          // get exchange record and loop to try again on `InvalidStateError`
          const {workflow, exchangeRecord: {exchange}} = this;
          this.exchangeRecord = await exchanges.get({
            workflowId: workflow.id, id: exchange.id
          });
          continue;
        }
        // rethrow in all other cases
        throw e;
      }
    }
  }

  async _validateReceivedPresentation({
    workflow, exchange, step, receivedPresentation, verify
  }) {
    // 1. Set `isEnvelopedPresentation` to `true` if the received presentation's
    // type is `EnvelopedVerifiablePresentation`, otherwise set it to `false`.
    const isEnvelopedPresentation =
      receivedPresentation?.type === 'EnvelopedVerifiablePresentation';

    // 2. If `step.presentationSchema` is set and `isEnvelopedPresentation` is
    // `false`, then use the presentation schema to validate
    // `receivedPresentation`, throwing an error if validation fails.
    const {presentationSchema} = step;
    if(presentationSchema && !isEnvelopedPresentation) {
      validateVerifiablePresentation({
        schema: presentationSchema.jsonSchema,
        presentation: receivedPresentation
      });
    }

    // 3. Set `expectedChallenge` to the local exchange ID if the exchange is on
    // the initial step, otherwise set it to the `challenge` property's value in
    // `exchange.variables.results[exchange.step].responsePresentationRequest`
    // if it is set, otherwise set it to `undefined` (for subsequent steps,
    // an implementation may also set the challenge in an
    // implementation-specific way).
    const isInitialStep = _isInitialStep({workflow, exchange});
    const responsePresentationRequest = exchange.variables
      .results?.[exchange.step]?.responsePresentationRequest;
    const expectedChallenge = isInitialStep ?
      exchange.id : responsePresentationRequest?.challenge;

    // 4. Set `expectedDomain` to the `domain` property's value in
    // `exchange.variables.results[exchange.step].responsePresentationRequest`
    // if it is set, otherwise set it to the `domain` property's value in
    // `step.verifiablePresentationRequest` if it is set, otherwise set it to
    // the origin value for `workflow.id`.
    const expectedDomain = responsePresentationRequest?.domain ??
      step.verifiablePresentationRequest?.domain ?? new URL(workflow.id).origin;

    // 5. Verify the received presentation (e.g., using a configured VCALM
    // verifier instance):
    const {
      allowUnprotectedPresentation = false,
      verifyPresentationResultSchema
    } = step;
    const verifyPresentationOptions = structuredClone(
      step.verifyPresentationOptions ?? {});
    const verifyResult = await verify({
      workflow, exchange, step,
      verifyPresentationOptions,
      verifyPresentationResultSchema,
      verifiablePresentationRequest: responsePresentationRequest ??
        step.verifiablePresentationRequest,
      presentation: receivedPresentation,
      allowUnprotectedPresentation,
      expectedChallenge,
      expectedDomain
    });

    // build unenveloped verifiable presentation from verification results
    const verifiablePresentation = buildPresentationFromResults({
      presentation: receivedPresentation,
      verifyResult
    });

    // 4. If `step.presentationSchema` is set and `isEnvelopedPresentation` is
    // `true`, then use the presentation schema to validate the unenveloped
    // presentation returned from the verification process, throwing an error
    // if validation fails.
    if(presentationSchema && isEnvelopedPresentation) {
      validateVerifiablePresentation({
        schema: presentationSchema.jsonSchema,
        presentation: verifiablePresentation
      });
    }

    // FIXME: check the VP against "allowedIssuer" in VPR, if provided

    // 5. Set the verification results in
    // `exchange.variables.results[exchange.step]`.
    const {verificationMethod} = verifyResult;
    exchange.variables.results[exchange.step] = {
      ...exchange.variables.results[exchange.step],
      // common use case of DID Authentication; provide `did` for ease
      // of use in templates and consistency with OID4VCI which only
      // receives `did` not verification method nor VP
      did: verificationMethod?.controller || null,
      verificationMethod,
      verifiablePresentation,
      verifyPresentationResults: buildVerifyPresentationResults({verifyResult})
    };
  }

  async _validateReceivedPresentationRequest({
    exchange, step, receivedPresentationRequest
  }) {
    // 1. If `step.presentationRequestSchema` is set, then use the presentation
    // request schema to validate `receivedPresentationRequest`, throwing an
    // error if validation fails.
    if(step.presentationRequestSchema) {
      validateVerifiablePresentationRequest({
        schema: step.presentationRequestSchema.jsonSchema,
        presentationRequest: receivedPresentationRequest
      });
    }

    // 2. Set the presentation request in
    // `exchange.variables.results[exchange.step].receivedPresentationRequest`
    // so it can be used in subsequent steps.
    exchange.variables.results[exchange.step] = {
      ...exchange.variables.results[exchange.step],
      receivedPresentationRequest
    };
  }

  async _tryProcess({
    receivedPresentation, receivedPresentationRequest, retryState
  } = {}) {
    const {workflow, exchangeRecord, prepareStep, inputRequired} = this;
    const {exchange, meta} = exchangeRecord;

    // initialize exchange results
    if(!exchange.variables.results) {
      exchange.variables.results = {};
    }

    // 1. Initialize `step` and `response` to `null`.
    let step = null;
    let response = null;

    // track whether issuance has been triggered yet to set retry capability
    let issuanceTriggered = false;

    try {
      // 2. If `exchange.state` is `complete` or `invalid`, throw a
      // `NotAllowedError`.
      if(exchange.state === 'complete' || exchange.state === 'invalid') {
        throw new BedrockError(`Exchange is ${exchange.state}`, {
          name: 'NotAllowedError',
          details: {httpStatusCode: 403, public: true}
        });
      }

      // 3. If `exchange.state` is `pending`, set it to `active`.
      if(exchange.state === 'pending') {
        exchange.state = 'active';
      }

      // 4. Continuously loop to process exchange steps, optionally saving any
      // error thrown as `exchange.lastError`. Other algorithm steps will
      // return out of the loop when a full response is generated, input from
      // the exchange client is required, or the exchange times out. An
      // implementation specific maximum step count be optionally enforced to
      // prevent misconfigured workflows.
      let stepCount = 0;
      const signal = _createTimeoutSignal({exchange, meta});
      while(true) {
        if(signal.aborted) {
          throw new BedrockError('Exchange has expired.', {
            name: 'DataError',
            details: {httpStatusCode: 500, public: true}
          });
        }
        if(stepCount++ > MAXIMUM_STEP_COUNT) {
          throw new BedrockError('Maximum step count exceeded.', {
            name: 'DataError',
            details: {httpStatusCode: 500, public: true}
          });
        }

        // 4.1. Set `step` to the current step (evaluating a step template as
        // needed).
        step = await _getStep({workflow, exchange});

        // 4.2. Call subalgorithm `prepareStep`, passing `workflow`,
        // `exchange`, `step`, `receivedPresentation`, and
        // `receivedPresentationRequest` to perform any protocol-specific
        // custom step preparation. If `prepareStep` returns a `prepareResult`
        // with `receivedPresentation` and/or `receivedPresentationRequest` set,
        // then update `receivedPresentation` and/or
        // `receivedPresentationRequest` accordingly.
        const prepareResult = await prepareStep?.({
          workflow, exchange, step,
          receivedPresentation, receivedPresentationRequest
        });
        if(prepareResult?.receivedPresentation !== undefined) {
          receivedPresentation = prepareResult.receivedPresentation;
        }
        if(prepareResult?.receivedPresentationRequest) {
          receivedPresentationRequest =
            prepareResult.receivedPresentationRequest;
        }

        // 4.3. If `receivedPresentation` is set, then call the
        // `validateReceivedPresentation` sub-algorithm, passing `workflow`,
        // `exchange`, `step`, and `receivedPresentation`.
        if(receivedPresentation) {
          await this._validateReceivedPresentation({
            workflow, exchange, step, receivedPresentation,
            verify: this.verify
          });
        }

        // 4.4. If `receivedPresentationRequest` is set, call the
        // `validateReceivedPresentationRequest` sub-algorithm, passing
        // `exchange`, `step`, and `receivedPresentationRequest`.
        if(receivedPresentationRequest) {
          await this._validateReceivedPresentationRequest({
            exchange, step, receivedPresentationRequest
          });
        }

        // 4.5. If the implementation supports blocking callbacks that can
        // return results to be added to exchange variables (or return errors),
        // call the callback and store its results in
        // `exchange.variables.results[exchange.step].callbackResults` or
        // throw any error received.
        // FIXME: to be implemented

        // 4.6. Set `isInputRequired` to the result of calling
        // `inputRequired({step, receivedPresentation})`.
        const isInputRequired = await inputRequired?.({
          workflow, exchange, step, receivedPresentation
        }) ?? false;

        // 4.7. If `isInputRequired` is true:
        if(isInputRequired) {
          // 4.7.1. If `response` is `null`, set it to an empty object.
          if(!response) {
            response = {};
          }

          // 4.7.2. If `step.verifiablePresentationRequest` is set, call
          // the `createVerifiablePresentationRequest` sub-algorithm, passing
          // `workflow`, `exchange`, `step`, and `response`.
          if(step.verifiablePresentationRequest) {
            await _createVerifiablePresentationRequest({
              workflow, exchange, step, response
            });
          }

          // 4.7.3. Save the exchange (and call any non-blocking callback
          // in the step) and return `response`.
          await _updateExchange({workflow, exchange, meta, step});
          return response;
        }

        // 4.8. Set `issueToClient` to `true` if `step.issueRequests` includes
        // any issuer requests for VCs that are to be sent to the client
        // (`issueRequest.result` is NOT set), otherwise set it to `false`.
        const issueRequestsParams = getIssueRequestsParams({
          workflow, exchange, step
        });
        const issueToClient = issueRequestsParams.some(p => !p.result);

        // 4.9. If `step.verifiablePresentation` is set or `issueToClient` is
        // `true`:
        if(step.verifiablePresentation || issueToClient) {
          // 4.9.1. If `response` is not `null`
          if(response) {
            // 4.9.1.1. If `response.verifiablePresentationRequest` is not set,
            // set it to an empty object (to indicate that the exchange is
            // not yet complete).
            if(!response.verifiablePresentationRequest) {
              response.verifiablePresentationRequest = {};
            }
            // 4.9.1.2. Save the exchange (and call any non-blocking callback
            // in the step).
            await _updateExchange({workflow, exchange, meta, step});
            // 4.9.1.3. Return `response`.
            return response;
          }

          // 4.9.2. Set `response` to an empty object.
          response = {};

          // 4.9.3. If `step.verifiablePresentation` is set, set
          // `response.verifiablePresentation` to a copy of it, otherwise
          // set `response.verifiablePresentation` to a new, empty,
          // Verifiable Presentation (using VCDM 2.0 by default, but a custom
          // configuration could specify another version).
          response.verifiablePresentation =
            structuredClone(step.verifiablePresentation) ??
            createPresentation();
        }

        // issuance has been triggered
        issuanceTriggered = true;

        // 4.10. Perform every issue request (optionally in parallel),
        // returning an error response to the client if any fails (note:
        // implementations can optionally implement failure recovery or retry
        // issue requests at their own discretion):
        // 4.10.1. For each issue request where `result` is set to an exchange
        // variable path or name, save the issued credential in the referenced
        // exchange variable.
        // 4.10.2. For each issue request where `result` is not specified, save
        // the issued credential in `response.verifiablePresentation`, i.e.,
        // for a VCDM presentation, append the issued credential to
        // `response.verifiablePresentation.verifiableCredential`.
        await this.issue({
          workflow, exchange, step, issueRequestsParams,
          verifiablePresentation: response?.verifiablePresentation
        });

        // 4.11. If `response.verifiablePresentation` is set and the step
        // configuration indicates it should be signed, sign the presentation
        // (e.g., by using a VCALM holder instance's `/presentations/create`
        // endpoint).
        // FIXME: implement
        //if(response?.verifiablePresentation) {}

        // 4.12. If `step.redirectUrl` is set:
        if(step.redirectUrl) {
          // 4.12.1. If `response` is `null` then set it to an empty object.
          if(!response) {
            response = {};
          }
          // 4.12.2. Set `response.redirectUrl` to `step.redirectUrl`.
          response.redirectUrl = step.redirectUrl;
        }

        // 4.13. If `step.nextStep` is not set then set `exchange.state` to
        // `complete`.
        if(!step.nextStep) {
          exchange.state = 'complete';
        } else {
          // 4.14. Otherwise, delete `exchange.variables.results[step.nextStep]`
          // if it exists, and set `exchange.step` to `step.nextStep`.
          delete exchange.variables.results[step.nextStep];
          exchange.step = step.nextStep;
        }

        // 4.15. Save the exchange (and call any non-blocking callback in
        // the step).
        await _updateExchange({workflow, exchange, meta, step});

        // 4.16. If `exchange.state` is `complete`, return `response` if it is
        // not `null`, otherwise return an empty object.
        if(exchange.state === 'complete') {
          return response ?? {};
        }

        // 4.17. Set `receivedPresentation` to `null`.
        receivedPresentation = null;
      }
    } catch(e) {
      if(e.name === 'InvalidStateError') {
        retryState.canRetry = !issuanceTriggered;
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
    // return default empty step and set dummy stepname for exchange
    exchange.step = 'initial';
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

async function _createVerifiablePresentationRequest({
  workflow, exchange, step, response
}) {
  // 1. Set `response.verifiablePresentationRequest` to
  // a copy of `step.verifiablePresentationRequest`.
  response.verifiablePresentationRequest =
    structuredClone(step.verifiablePresentationRequest);

  // 2. If `step.createChallenge` is `false`, return.
  if(!step.createChallenge) {
    return;
  }

  // 3. Set `response.verifiablePresentationRequest.challenge` to an
  // appropriate challenge value (e.g., use a configured VCALM verifier
  // instance's `/challenges` endpoint).
  /* Note: When setting the challenge, if the exchange on the initial step,
  the challenge is the local exchange ID. Any subsequent step requires
  a different challenge value. */
  let challenge;
  const isInitialStep = _isInitialStep({workflow, exchange});
  if(isInitialStep) {
    challenge = exchange.id;
  } else {
    // generate a new challenge using verifier API
    ({challenge} = await createChallenge({workflow}));
  }
  response.verifiablePresentationRequest.challenge = challenge;

  // 4. Set `exchange.variables.results[exchange.step]` to an object with the
  // property `responsePresentationRequest` set to
  // `response.verifiablePresentationRequest`.
  exchange.variables.results[exchange.step] = {
    responsePresentationRequest: response.verifiablePresentationRequest
  };
}

function _isInitialStep({workflow, exchange}) {
  return !workflow.initialStep || exchange.step === workflow.initialStep;
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
