/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const {config} = bedrock;

const namespace = 'vc-delivery';
const cfg = config[namespace] = {};

const basePath = '/foo';
cfg.routes = {
  basePath
};
