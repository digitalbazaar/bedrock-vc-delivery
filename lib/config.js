/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import '@bedrock/express';

const c = bedrock.util.config.main;
const cc = c.computer();
const {config} = bedrock;

// use `vc-workflow` namespace
const namespace = 'vc-workflow';
config[namespace] = {};

config[namespace].exchanges = {
  variablesGarbageCollector: {
    // collect expired externalized exchange "variables" every 5 minutes; may
    // be slightly randomized
    // default: 5 minutes
    interval: 5 * 60 * 1000
  }
};

// create dev application identity for vc-workflow (must be overridden in
// deployments) ...and `ensureConfigOverride` has already been set via
// `bedrock-app-identity` so it doesn't have to be set here
config['app-identity'].seeds.services['vc-workflow'] = {
  id: 'did:key:z6MknmKKxYiYo6txxX2bCgzeuBDkPPb5SJ36p232XkVEk7mf',
  seedMultibase: 'z1Abgbd91bbZHPYakVA7EPvhY9NZ2EaTkEpmwdBCfifokDn',
  serviceType: 'vc-workflow'
};

// backwards compatibility: `vc-exchanger` alias:
cc('vc-exchanger', () => config[namespace]);
config['app-identity'].seeds.services['vc-exchanger'] = {
  serviceType: 'vc-exchanger'
};
cc('app-identity.seeds.services.vc-exchanger.id', () =>
  config['app-identity'].seeds.services['vc-workflow'].id);
cc('app-identity.seeds.services.vc-exchanger.seedMultibase', () =>
  config['app-identity'].seeds.services['vc-workflow'].seedMultibase);

// set body parser limits for workflow endpoints (and deprecated `/exchangers`)
const routePrefixes = ['/workflows', '/exchangers'];
const createBodyParserOptions = ({limit}) => ({
  json: {
    strict: false,
    limit,
    type: ['json', '+json']
  }
});
const bodyParserRoutes = config.express.bodyParser.routes;
for(const routePrefix of routePrefixes) {
  // exchange clients POST to this route to execute exchanges; limit indicates
  // how large submitted VPs can be
  bodyParserRoutes[
    `${routePrefix}/:localWorkflowId/exchanges/:localExchangeId`
  ] = createBodyParserOptions({limit: '10MB'});
  // exchanges are created using this route; limit indicates how large
  // variables can be (in total)
  bodyParserRoutes[
    `${routePrefix}/:localWorkflowId/exchanges`
  ] = createBodyParserOptions({limit: '10MB'});
}
