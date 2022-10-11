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

// FIXME: rename to `create` and name file `authorizationService.js`
// FIXME: method for adding AS routes
export async function createAuthorizationService({app} = {}) {
  // FIXME: pass in base route instead; do not use config
  const {routes} = config['vc-delivery'];

  // FIXME: provide method to create / add AS; use in tests, but it
  // would be a different system from the DS -- DS needs to be configured
  // to accept access tokens from from the AS
  // ...DS would be represented as an ephemeral OIDC4VCI exchange, with the AS
  // ...issuer listed as the OAuth2 authority to check access tokens against

  // FIXME: determine if each exchange can be its own OpenID provider, serving
  // its own meta-data:
  // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  // GET /issuer1/.well-known/openid-configuration HTTP/1.1
  // Host: example.com
  // ... whereby `issuer1` appears here: `https://example.com/issuer1`
  // ... or really like so:
  // `https://example.com/exchangers/z12...123/exchanges/z64...123123` with:
  // GET /exchangers/z12...123/exchanges/z64...123123/.well-known/openid-...`
  // FIXME: implemented on AS (authorization server)
  app.post(
    routes.basePath + '/token',
    asyncHandler(async (req, res) => {
      // pre-authz code request:
      // grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
      // &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
      // &user_pin=493536
      const body = {
        access_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ',
        token_type: 'bearer',
        expires_in: 86400
      };
      res.json(body);

      // OR:

      // authz code request:
      // grant_type=authorization_code
      // &code=SplxlOBeZQQYbYS6WxSbIA
      // &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
      // &redirect_uri=https%3A%2F%2FWallet.example.org%2Fcb
    }));
}

async function _discoverClient({} = {}) {
  // FIXME: implement oauth client discovery
}
