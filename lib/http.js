/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {asyncHandler} from '@bedrock/express';

const {config} = bedrock;

bedrock.events.on('bedrock-express.configure.routes', app => {
  const {routes} = config['module-template-http'];
  app.post(
    routes.basePath,
    asyncHandler(async (/*req, res*/) => {
    }));
});
