/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {createService, schemas} from '@bedrock/service-core';
import {addRoutes} from './http.js';
import {initializeServiceAgent} from '@bedrock/service-agent';
import {klona} from 'klona';
import '@bedrock/express';

// load config defaults
import './config.js';

export * as oidc4vci from './oidc4vci/index.js';

const serviceType = 'vc-exchanger';

bedrock.events.on('bedrock.init', async () => {
  // add customizations to config validators...
  const createConfigBody = klona(schemas.createConfigBody);
  const updateConfigBody = klona(schemas.updateConfigBody);
  // const schemasToUpdate = [createConfigBody, updateConfigBody];
  // for(const schema of schemasToUpdate) {
  //   // FIXME: add config requirements to exchanger configs
  //   schema.properties.foo = someImportedSchema;
  //   schema.required.push('baz');
  //   schema.properties.baz = someOtherImportedSchema;
  // }

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
      // FIXME: add custom validate config function
      //validateConfigFn,
      // FIXME: determine storage
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
    usageAggregator: _aggregateUsage
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

async function _aggregateUsage({meter, signal, service} = {}) {
  const {id: meterId} = meter;
  // FIXME: add `exchanges` storage
  return service.configStorage.getUsage({meterId, signal});
}
