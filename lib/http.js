/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from './exchanges.js';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {createExchangeBody} from '../schemas/bedrock-vc-exchanger.js';
import {generateRandom} from './helpers.js';
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

  // FIXME: rename to `vc-exchanger` now or later?
  const cfg = bedrock.config['vc-delivery'];
  const baseUrl = `${routePrefix}/:localId`;
  const routes = {
    exchanges: `${baseUrl}/exchanges`,
    exchange: `${baseUrl}/exchanges/:exchangeId`
  };

  const getConfigMiddleware = middleware.createGetConfigMiddleware({service});

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
      try {
        const {config} = req.serviceObject;
        const {variables} = req.body;

        // FIXME: see which variables are required by `config` and ensure
        // that they are present
        if(!variables.foo) {
          throw new BedrockError('"foo" variable is required.', {
            name: 'DataError',
            details: {httpStatusCode: 400, public: true}
          });
        }

        // insert exchange
        const {id: exchangerId} = config;
        const exchange = {
          id: await generateRandom(),
          // FIXME: use `step=<num>` instead?
          complete: false
        }
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

  // FIXME: add delivery service; support multiple protocols
}
