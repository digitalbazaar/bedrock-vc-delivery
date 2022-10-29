/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from './exchanges.js';
import * as oidc4vci from './oidc4vci.js';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {createExchangeBody} from '../schemas/bedrock-vc-exchanger.js';
import {decodeLocalId, generateRandom} from './helpers.js';
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
    // save promise in request, do not wait for it to settle
    req.exchange = exchanges.get({exchangerId, id});
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
        const {ttl, variables = {}} = req.body;

        // FIXME: see which variables are required by `config` and ensure
        // that they are present
        /*if(!variables.foo) {
          throw new BedrockError('"foo" variable is required.', {
            name: 'DataError',
            details: {httpStatusCode: 400, public: true}
          });
        }*/

        // insert exchange
        const {id: exchangerId} = config;
        const exchange = {
          id: await generateRandom(),
          ttl
          // FIXME: add initial `step` if specified in `config`
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

  // VC-API exchange endpoint
  app.post(
    routes.exchange,
    getExchange,
    getConfigMiddleware,
    asyncHandler(async (req, res) => {
      // FIXME: determine requirements for this exchange from the exchanger
      //const {config: exchanger} = req.serviceObject;

      // FIXME: if data is empty:
      // 1. if VPR is required, send it
      // 2. otherwise, issue VCs and complete exchange

      // FIXME: if data is not empty
      // 1. ensure data matches what is required for current exchange step,
      //    otherwise send error
      // 2. send encrypted / issued VCs in a VP or go to next step

      // FIXME: implement
      res.status(400).json({error: 'not implemented'});
    }));

  // create OIDC4VCI routes to be used with each individual exchange
  await oidc4vci.createRoutes(
    {app, exchangeRoute: routes.exchange, getConfigMiddleware, getExchange});
}
