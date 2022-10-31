/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as exchangerSchemas from '../schemas/bedrock-vc-exchanger.js';
import {createService, schemas} from '@bedrock/service-core';
import {addRoutes} from './http.js';
import {initializeServiceAgent} from '@bedrock/service-agent';
import {klona} from 'klona';
import '@bedrock/express';

// load config defaults
import './config.js';

const serviceType = 'vc-exchanger';
const {util: {BedrockError}} = bedrock;

bedrock.events.on('bedrock.init', async () => {
  // add customizations to config validators...
  const createConfigBody = klona(schemas.createConfigBody);
  const updateConfigBody = klona(schemas.updateConfigBody);
  const schemasToUpdate = [createConfigBody, updateConfigBody];
  const {credentialTemplates, steps, initialStep} = exchangerSchemas;
  for(const schema of schemasToUpdate) {
    // add config requirements to exchanger configs
    schema.properties.credentialTemplates = credentialTemplates;
    schema.properties.steps = steps;
    schema.properties.initialStep = initialStep;
    // note: credential templates are not required; if any other properties
    // become required, add them here
    // schema.required.push('credentialTemplates');
  }

  // create `vc-exchanger` service
  const service = await createService({
    serviceType,
    routePrefix: '/exchangers',
    storageCost: {
      config: 1,
      revocation: 1
    },
    validation: {
      createConfigBody,
      updateConfigBody,
      validateConfigFn,
      // these zcaps are optional (by reference ID)
      zcapReferenceIds: [{
        referenceId: 'issue',
        required: false
      }, {
        referenceId: 'credentialStatus',
        required: false
      }, {
        referenceId: 'verifyPresentation',
        required: false
      }]
    },
    usageAggregator
  });

  bedrock.events.on('bedrock-express.configure.routes', async app => {
    await addRoutes({app, service});
  });

  // initialize vc-exchanger service agent early (after database is ready) if
  // KMS system is externalized; otherwise we must wait until KMS system
  // is ready
  const externalKms = !bedrock.config['service-agent'].kms.baseUrl.startsWith(
    bedrock.config.server.baseUri);
  const event = externalKms ? 'bedrock-mongodb.ready' : 'bedrock.ready';
  bedrock.events.on(event, async () => {
    await initializeServiceAgent({serviceType});
  });
});

async function usageAggregator({meter, signal, service} = {}) {
  const {id: meterId} = meter;
  // FIXME: add `exchanges` storage
  return service.configStorage.getUsage({meterId, signal});
}

async function validateConfigFn({config} = {}) {
  try {
    // if credential templates are specified, then `zcaps` MUST include at
    // least `issue`
    const {credentialTemplates = [], zcaps = {}} = config;
    if(credentialTemplates.length > 0 && !zcaps.issue) {
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

    // if `steps` are specified, then `initialStep` MUST be included
    const {steps = [], initialStep} = config;
    if(steps.length > 0 && initialStep === undefined) {
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
