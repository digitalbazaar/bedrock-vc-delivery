/*!
 * Copyright (c) 2018-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchanges from './exchanges.js';
import * as oid4 from './oid4/http.js';
import {createExchange, processExchange} from './vcapi.js';
import {
  createExchangeBody, useExchangeBody
} from '../schemas/bedrock-vc-workflow.js';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {getWorkflowId} from './helpers.js';
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
    exchange: `${baseUrl}/exchanges/:exchangeId`,
    protocols: `${baseUrl}/exchanges/:exchangeId/protocols`
  };

  // used to retrieve service object (workflow) config
  const getConfigMiddleware = middleware.createGetConfigMiddleware({service});

  // used to fetch exchange record in parallel
  const getExchange = asyncHandler(async (req, res, next) => {
    const {localId, exchangeId: id} = req.params;
    const workflowId = getWorkflowId({routePrefix, localId});
    // expose access to result via `req`; do not wait for it to settle here
    const exchangePromise = exchanges.get({workflowId, id}).catch(e => e);
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
        const {config: workflow} = req.serviceObject;
        const {
          ttl, openId, variables = {},
          // allow steps to be skipped by creator as needed
          step = workflow.initialStep
        } = req.body;
        const exchange = {ttl, openId, variables, step};
        const {id} = await createExchange({workflow, exchange});
        const location = `${workflow.id}/exchanges/${id}`;
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
      const {config: workflow} = req.serviceObject;
      const exchangeRecord = await req.getExchange();
      await processExchange({req, res, workflow, exchangeRecord});
    }));

  // VC-API get interaction `{"protocols": {...}}` options
  app.get(
    routes.protocols,
    cors(),
    getExchange,
    getConfigMiddleware,
    asyncHandler(async (req, res) => {
      if(!req.accepts('json')) {
        // provide hopefully useful error for when VC API interaction URLs
        // are processed improperly, e.g., directly loaded by a browser instead
        // of by a digital wallet
        throw new BedrockError(
          'Unsupported "Accept" header. A VC API interaction URL must be ' +
          'processed by an exchange client, e.g., a digital wallet.', {
            name: 'NotSupportedError',
            details: {httpStatusCode: 406, public: true}
          });
      }
      // construct and return `protocols` object
      const {config: workflow} = req.serviceObject;
      const {exchange} = await req.getExchange();
      const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
      const protocols = {
        vcapi: exchangeId
      };
      const openIdRoute = `${exchangeId}/openid`;
      if(oid4.supportsOID4VCI({exchange})) {
        // OID4VCI supported; add credential offer URL
        const searchParams = new URLSearchParams();
        const uri = `${openIdRoute}/credential-offer`;
        searchParams.set('credential_offer_uri', uri);
        protocols.OID4VCI = `openid-credential-offer://?${searchParams}`;
      } else if(await oid4.supportsOID4VP({workflow, exchange})) {
        // OID4VP supported; add openid4vp URL
        const searchParams = new URLSearchParams({
          client_id: `${openIdRoute}/client/authorization/response`,
          request_uri: `${openIdRoute}/client/authorization/request`
        });
        protocols.OID4VP = `openid4vp://?${searchParams}`;
      }
      res.json({protocols});
    }));

  // create OID4* routes to be used with each individual exchange
  await oid4.createRoutes(
    {app, exchangeRoute: routes.exchange, getConfigMiddleware, getExchange});
}
