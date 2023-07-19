/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const {config} = bedrock;

// use `vc-exchanger` namespace
const namespace = 'vc-exchanger';
config[namespace] = {};

// create dev application identity for vc-exchanger (must be overridden in
// deployments) ...and `ensureConfigOverride` has already been set via
// `bedrock-app-identity` so it doesn't have to be set here
config['app-identity'].seeds.services['vc-exchanger'] = {
  id: 'did:key:z6MknmKKxYiYo6txxX2bCgzeuBDkPPb5SJ36p232XkVEk7mf',
  seedMultibase: 'z1Abgbd91bbZHPYakVA7EPvhY9NZ2EaTkEpmwdBCfifokDn',
  serviceType: 'vc-exchanger'
};
