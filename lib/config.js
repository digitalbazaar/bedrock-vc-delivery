/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const {config} = bedrock;

// FIXME: consider rename to `vc-exchanger`
const namespace = 'vc-delivery';
const cfg = config[namespace] = {};
