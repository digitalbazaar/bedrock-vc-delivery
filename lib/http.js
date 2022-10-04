/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {asyncHandler} from '@bedrock/express';

const {config} = bedrock;

// FIXME: change to expose functions to create services that can be called
// by the top level application -- and to mount the AS / credential issuance
// endpoints appropriately
// bedrock.events.on('bedrock-express.configure.routes', app => {
// });
