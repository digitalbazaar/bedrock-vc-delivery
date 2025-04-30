/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as workflowSchemas from '../schemas/bedrock-vc-workflow.js';
import {createService, schemas} from '@bedrock/service-core';
import {addRoutes} from './http.js';
import {initializeServiceAgent} from '@bedrock/service-agent';
import {MAX_ISSUER_INSTANCES} from './constants.js';
import {parseLocalId} from './helpers.js';
import '@bedrock/express';

// load config defaults
import './config.js';

const {util: {BedrockError}} = bedrock;

bedrock.events.on('bedrock.init', async () => {
  await _initService({serviceType: 'vc-workflow', routePrefix: '/workflows'});
  // backwards compatibility: deprecrated `exchangers` service
  await _initService({serviceType: 'vc-exchanger', routePrefix: '/exchangers'});
});

async function _initService({serviceType, routePrefix}) {
  // add customizations to config validators...
  const createConfigBody = structuredClone(schemas.createConfigBody);
  const updateConfigBody = structuredClone(schemas.updateConfigBody);
  const schemasToUpdate = [createConfigBody, updateConfigBody];
  const {
    credentialTemplates, steps, initialStep, issuerInstances
  } = workflowSchemas;
  for(const schema of schemasToUpdate) {
    // add config requirements to workflow configs
    schema.properties.credentialTemplates = credentialTemplates;
    schema.properties.steps = steps;
    schema.properties.initialStep = initialStep;
    schema.properties.issuerInstances = issuerInstances;
    // allow zcaps by custom reference ID
    schema.properties.zcaps = structuredClone(schemas.zcaps);
    // max of 4 basic zcaps + max issuer instances
    schema.properties.zcaps.maxProperties = 4 + MAX_ISSUER_INSTANCES;
    schema.properties.zcaps.additionalProperties = schemas.delegatedZcap;
    // note: credential templates are not required; if any other properties
    // become required, add them here
    // schema.required.push('credentialTemplates');
  }

  // allow `id` property in `createConfigBody`, to be more rigorously validated
  // below in `validateConfigFn`
  createConfigBody.properties.id = updateConfigBody.properties.id;

  // create workflow service
  const service = await createService({
    serviceType,
    routePrefix,
    storageCost: {
      config: 1,
      revocation: 1
    },
    validation: {
      createConfigBody,
      updateConfigBody,
      async validateConfigFn({config, op} = {}) {
        return validateConfigFn({config, op, routePrefix});
      },
      // these zcaps are optional (by reference ID)
      zcapReferenceIds: [{
        referenceId: 'issue',
        required: false
      }, {
        referenceId: 'credentialStatus',
        required: false
      }, {
        referenceId: 'createChallenge',
        required: false
      }, {
        referenceId: 'verifyPresentation',
        required: false
      }]
    },
    async usageAggregator({meter, signal} = {}) {
      return usageAggregator({meter, signal, service});
    }
  });

  bedrock.events.on('bedrock-express.configure.routes', async app => {
    await addRoutes({app, service});
  });

  // initialize vc-workflow service agent early (after database is ready) if
  // KMS system is externalized; otherwise we must wait until KMS system
  // is ready
  const externalKms = !bedrock.config['service-agent'].kms.baseUrl.startsWith(
    bedrock.config.server.baseUri);
  const event = externalKms ? 'bedrock-mongodb.ready' : 'bedrock.ready';
  bedrock.events.on(event, async () => {
    await initializeServiceAgent({serviceType});
  });
}

async function usageAggregator({meter, signal, service} = {}) {
  const {id: meterId} = meter;
  // FIXME: add `exchanges` storage
  return service.configStorage.getUsage({meterId, signal});
}

async function validateConfigFn({config, op, routePrefix} = {}) {
  try {
    // validate any `id` in a new config
    if(op === 'create' && config.id !== undefined) {
      try {
        _validateId({id: config.id, routePrefix});
      } catch(e) {
        throw new BedrockError(
          `Invalid client-provided configuration ID: ${e.message}.`, {
            name: 'DataError',
            details: {
              httpStatusCode: 400,
              public: true
            },
            cause: e
          });
      }
    }

    // if credential templates are specified, then `zcaps` MUST include at
    // least `issue`
    const {credentialTemplates = [], zcaps = {}, issuerInstances} = config;
    if(credentialTemplates.length > 0) {
      if(!(zcaps.issue || issuerInstances)) {
        throw new BedrockError(
          'A capability to issue credentials is required when credential ' +
          'templates are provided.', {
            name: 'DataError',
            details: {
              httpStatusCode: 400,
              public: true
            }
          });
      }
      // ensure that, if `issuerInstances` is given, that every zcap
      // referenced in each issuer instance config's `zcapReferenceIds` can
      // be found in `zcaps`
      if(issuerInstances) {
        if(!issuerInstances.every(
          instance => !!zcaps[instance.zcapReferenceIds.issue])) {
          throw new BedrockError(
            'An issuer instance configuration zcap reference ID is not ' +
            'present in "config.zcaps".', {
              name: 'DataError',
              details: {
                httpStatusCode: 400,
                public: true
              }
            });
        }
      }
    }

    // if `steps` are specified, then `initialStep` MUST be included
    const {steps, initialStep} = config;
    if(steps && initialStep === undefined) {
      throw new BedrockError(
        '"initialStep" is required when "steps" are provided.', {
          name: 'DataError',
          details: {
            httpStatusCode: 400,
            public: true
          }
        });
    }
  } catch(error) {
    return {valid: false, error};
  }
  return {valid: true};
}

function _validateId({id, routePrefix} = {}) {
  // format: <base>/<localId>

  // ensure `id` starts with appropriate base URL
  const {baseUri} = bedrock.config.server;
  const base = `${baseUri}${routePrefix}/`;
  if(id.startsWith(base)) {
    // ensure `id` ends with appropriate local ID
    const expectedLastSlashIndex = base.length - 1;
    const idx = id.lastIndexOf('/');
    if(idx === expectedLastSlashIndex) {
      return parseLocalId({id});
    }
  }

  throw new BedrockError(
    `Configuration "id" must start with "${base}" and end in a multibase, ` +
    'base58-encoded local identifier.', {
      name: 'DataError',
      details: {
        httpStatusCode: 400,
        public: true
      }
    });
}
