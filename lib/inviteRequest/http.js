/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as inviteRequest from './inviteRequest.js';
import {asyncHandler} from '@bedrock/express';
import cors from 'cors';
import {inviteResponseBody} from '../../schemas/bedrock-vc-workflow.js';
import {createValidateMiddleware as validate} from '@bedrock/validation';

// creates invite request endpoints for each individual exchange
export async function createRoutes({
  app, exchangeRoute, getConfigMiddleware, getExchange
} = {}) {
  const inviteRequestRoute = `${exchangeRoute}/invite-request`;
  const routes = {
    inviteResponse: `${inviteRequestRoute}/response`
  };

  // receives an invite response
  app.options(routes.inviteResponse, cors());
  app.post(
    routes.inviteResponse,
    cors(),
    validate({bodySchema: inviteResponseBody()}),
    getConfigMiddleware,
    getExchange,
    asyncHandler(_handleInviteResponse));
}

async function _handleInviteResponse(req, res) {
  const result = await inviteRequest.processInviteResponse({req});
  res.json(result);
}
