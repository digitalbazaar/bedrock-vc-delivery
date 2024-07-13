/*!
 * Copyright (c) 2018-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as _openId from './openId.js';
import * as bedrock from '@bedrock/core';
import * as exchanges from './exchanges.js';
import {
  createExchangeBody, useExchangeBody
} from '../schemas/bedrock-vc-workflow.js';
import {exportJWK, generateKeyPair, importJWK} from 'jose';
import {generateRandom, getWorkflowId} from './helpers.js';
import {metering, middleware} from '@bedrock/service-core';
import {asyncHandler} from '@bedrock/express';
import bodyParser from 'body-parser';
import cors from 'cors';
import {logger} from './logger.js';
import {processExchange} from './vcapi.js';
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

        if(openId) {
          /* Here we try to ensure an issuer instance is available that matches
          each of the expected credential definition requests. For simple
          configs, a single issuer instance is used with only an `issue` zcap
          and no other information, so we can't validate anything (we must just
          assume in that case clients will do the right thing. Otherwise, we
          try to make sure supported formats will match. */
          const {issuerInstances} = config;
          const singleIssuerInstance = config.zcaps.issue && !issuerInstances;
          if(!singleIssuerInstance) {
            /* credential requests look like:
            {
              format: 'ldp_vc',
              credential_definition: { '@context': [Array], type: [Array] }
            }
            */
            const {expectedCredentialRequests} = openId;
            // `expectedCredentialRequests` can have arrays of arrays that
            // indicate multiple options; every possible option must have at
            // least one issuer instance that could service it
            const match = expectedCredentialRequests.flat().every(
              ({format}) => issuerInstances.some(
                instance => instance.supportedFormats.includes(format)));
            if(!match) {
              throw new BedrockError(
                'Expected credential requests include a format not supported ' +
                'by this workflow.', {
                  name: 'DataError',
                  details: {httpStatusCode: 400, public: true}
                });
            }
          }

          // perform key generation if requested
          if(openId.oauth2?.generateKeyPair) {
            const {oauth2} = openId;
            const {algorithm} = oauth2.generateKeyPair;
            const kp = await generateKeyPair(algorithm, {extractable: true});
            const [privateKeyJwk, publicKeyJwk] = await Promise.all([
              exportJWK(kp.privateKey),
              exportJWK(kp.publicKey),
            ]);
            oauth2.keyPair = {privateKeyJwk, publicKeyJwk};
            delete oauth2.generateKeyPair;
          } else {
            // ensure key pair can be imported
            try {
              const {oauth2: {keyPair}} = openId;
              await Promise.all([
                importJWK(keyPair.privateKeyJwk),
                importJWK(keyPair.publicKeyJwk)
              ]);
            } catch(e) {
              throw new BedrockError(
                'Could not import OpenID OAuth2 key pair.', {
                  name: 'DataError',
                  details: {httpStatusCode: 400, public: true},
                  cause: e
                });
            }
          }
        }

        // insert exchange
        const {id: workflowId} = config;
        const exchange = {
          id: await generateRandom(),
          ttl,
          variables,
          openId,
          step
        };
        await exchanges.insert({workflowId, exchange});
        const location = `${workflowId}/exchanges/${exchange.id}`;
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
      const {exchange} = await req.getExchange();
      await processExchange({req, res, workflow, exchange});
    }));

  // create OID4VCI routes to be used with each individual exchange
  await _openId.createRoutes(
    {app, exchangeRoute: routes.exchange, getConfigMiddleware, getExchange});
}
