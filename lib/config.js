/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const c = bedrock.util.config.main;
const cc = c.computer();
const {config} = bedrock;

// use `vc-workflow` namespace
const namespace = 'vc-workflow';
config[namespace] = {};

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
