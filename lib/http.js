/*!
 * Copyright (c) 2018-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as _openId from './openId.js';
import * as bedrock from '@bedrock/core';
import * as exchanges from './exchanges.js';
import {createChallenge as _createChallenge, verify} from './verify.js';
import {
  createExchangeBody, useExchangeBody
} from '../schemas/bedrock-vc-exchanger.js';
import {exportJWK, generateKeyPair, importJWK} from 'jose';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {generateRandom} from './helpers.js';
import {issue} from './issue.js';
import {klona} from 'klona';
import {logger} from './logger.js';
import {createValidateMiddleware as validate} from '@bedrock/validation';

const {util: {BedrockError}} = bedrock;

// FIXME: remove and apply at top-level application
bedrock.events.on('bedrock-express.configure.bodyParser', app => {
  app.use(bodyParser.json({
    // allow json values that are not just objects or arrays
    strict: false,
    limit: '10MB',
    type: ['json', '+json']
  }));
});

export async function addRoutes({app, service} = {}) {
  const {routePrefix} = service;

  const baseUrl = `${routePrefix}/:localId`;
  const routes = {
    exchanges: `${baseUrl}/exchanges`,
    exchange: `${baseUrl}/exchanges/:exchangeId`
  };

  // used to retrieve service object (exchanger) config
  const getConfigMiddleware = middleware.createGetConfigMiddleware({service});

  // used to fetch exchange record in parallel
  const getExchange = asyncHandler(async (req, res, next) => {
    const {localId, exchangeId: id} = req.params;
    const {baseUri} = bedrock.config.server;
    const exchangerId = `${baseUri}${routePrefix}/${localId}`;
    // expose access to result via `req`; do not wait for it to settle here
    const exchangePromise = exchanges.get({exchangerId, id}).catch(e => e);
    req.getExchange = async () => {
      const record = await exchangePromise;
      if(record instanceof Error) {
        throw record;
      }
      return record;
    };
    next();
  });

  /* Note: CORS is used on all endpoints. This is safe because authorization
  uses HTTP signatures + capabilities or OAuth2, not cookies; CSRF is not
  possible. */

  // create an exchange
  app.options(routes.exchanges, cors());
  app.post(
    routes.exchanges,
    cors(),
    validate({bodySchema: createExchangeBody}),
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      // FIXME: check available storage via meter before allowing operation

      try {
        const {config} = req.serviceObject;
        const {
          ttl, openId, variables = {},
          // allow steps to be skipped by creator as needed
          step = config.initialStep
        } = req.body;

        // validate exchange step, if given
        if(step && !(step in config.steps)) {
          throw new BedrockError(`Undefined step "${step}".`, {
            name: 'DataError',
            details: {httpStatusCode: 400, public: true}
          });
        }

        // perform key generation if requested
        if(openId?.oauth2?.generateKeyPair) {
          const {oauth2} = openId;
          const {algorithm} = oauth2.generateKeyPair;
          const kp = await generateKeyPair(algorithm, {extractable: true});
          const [privateKeyJwk, publicKeyJwk] = await Promise.all([
            exportJWK(kp.privateKey),
            exportJWK(kp.publicKey),
          ]);
          oauth2.keyPair = {privateKeyJwk, publicKeyJwk};
          delete oauth2.generateKeyPair;
        } else if(openId) {
          // ensure key pair can be imported
          try {
            const {oauth2: {keyPair}} = openId;
            await Promise.all([
              importJWK(keyPair.privateKeyJwk),
              importJWK(keyPair.publicKeyJwk)
            ]);
          } catch(e) {
            throw new BedrockError('Could not import OpenID OAuth2 key pair.', {
              name: 'DataError',
              details: {httpStatusCode: 400, public: true},
              cause: e
            });
          }
        }

        // insert exchange
        const {id: exchangerId} = config;
        const exchange = {
          id: await generateRandom(),
          ttl,
          variables,
          openId,
          step
        };
        await exchanges.insert({exchangerId, exchange});
        const location = `${exchangerId}/exchanges/${exchange.id}`;
        res.status(204).location(location).send();
      } catch(error) {
        logger.error(error.message, {error});
        throw error;
      }

      // meter operation usage
      metering.reportOperationUsage({req});
    }));

  // VC-API get exchange endpoint
  app.get(
    routes.exchange,
    cors(),
    getExchange,
    getConfigMiddleware,
    middleware.authorizeServiceObjectRequest(),
    asyncHandler(async (req, res) => {
      const {exchange} = await req.getExchange();
      // do not return any oauth2 credentials
      delete exchange.openId?.oauth2?.keyPair?.privateKeyJwk;
      res.json({exchange});
    }));

  // VC-API use exchange endpoint
  app.options(routes.exchange, cors());
  app.post(
    routes.exchange,
    cors(),
    validate({bodySchema: useExchangeBody()}),
    getExchange,
    getConfigMiddleware,
    asyncHandler(async (req, res) => {
      const {config: exchanger} = req.serviceObject;
      const {exchange} = await req.getExchange();

      // get any `verifiablePresentation` from the body...
      let receivedPresentation = req?.body?.verifiablePresentation;

      // process exchange step(s)
      let currentStep = exchange.step;
      while(true) {
        // no step present, break out to complete exchange
        if(!currentStep) {
          break;
        }

        // get current step details
        const step = exchanger.steps[currentStep];

        // FIXME: if `step.template` exists, then we can assume it's the only
        // property and that `step.template.type` is `jsonata` due to schemas;
        // use `step.template.template` to generate the step to use against the
        // variables in the exchange state

        // handle VPR: if step requires it, then `verifiablePresentation` must
        // be in the request
        if(step.verifiablePresentationRequest) {
          const {createChallenge} = step;
          const isInitialStep = exchange.step === exchanger.initialStep;

          // if no presentation was received in the body...
          if(!receivedPresentation) {
            const verifiablePresentationRequest = klona(
              step.verifiablePresentationRequest);
            if(createChallenge) {
              /* Note: When creating a challenge, the initial step always
              uses the local exchange ID because the initial step itself
              is one-time use. Subsequent steps, which only VC-API (as opposed
              to other protocols) supports creating additional challenges via
              the VC-API verifier API. */
              let challenge;
              if(isInitialStep) {
                challenge = exchange.id;
              } else {
                // generate a new challenge using verifier API
                ({challenge} = await _createChallenge({exchanger}));
              }
              verifiablePresentationRequest.challenge = challenge;
            }
            // send VPR and return
            res.json({verifiablePresentationRequest});
            return;
          }

          // verify the received VP
          const expectedChallenge = isInitialStep ? exchange.id : undefined;
          const {verificationMethod} = await verify({
            exchanger, presentation: receivedPresentation, expectedChallenge
          });

          // FIXME: ensure VP satisfies step VPR

          // store VP results in variables associated with current step
          if(!exchange.variables.results) {
            exchange.variables.results = {};
          }
          exchange.variables.results[currentStep] = {
            // common use case of DID Authentication; provide `did` for ease
            // of use in templates and consistency with OID4VCI which only
            // receives `did` not verification method nor VP
            did: verificationMethod.controller,
            verificationMethod,
            verifiablePresentation: receivedPresentation
          };

          // clear received presentation as it has been processed
          receivedPresentation = null;

          // if there is no next step, break out to complete exchange
          if(!step.nextStep) {
            break;
          }

          // update the exchange to go to the next step, then loop to send
          // next VPR
          exchange.step = step.nextStep;
          await exchanges.update({
            exchangerId: exchanger.id, exchange, expectedStep: currentStep
          });
          currentStep = exchange.step;
        }
      }

      // mark exchange complete
      await exchanges.complete({
        exchangerId: exchanger.id, exchange, expectedStep: currentStep
      });

      // FIXME: decide what the best recovery path is if delivery fails (but no
      // replay attack detected) after exchange has been marked complete

      // issue VCs
      const {verifiablePresentation} = await issue({exchanger, exchange});

      // send VP
      res.json({verifiablePresentation});
    }));

  // create OID4VCI routes to be used with each individual exchange
  await _openId.createRoutes(
    {app, exchangeRoute: routes.exchange, getConfigMiddleware, getExchange});
}
