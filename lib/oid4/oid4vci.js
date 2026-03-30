/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as draft13 from './oid4vciDraft13.js';
import {issue as defaultIssue, getIssueRequestsParams} from '../issue.js';
import {getWorkflowIssuerInstances, setVariable} from '../helpers.js';
import {importJWK, SignJWT} from 'jose';
import {timingSafeEqual, randomUUID as uuid} from 'node:crypto';
import {
  authorizationDetails as authorizationDetailsSchema
} from '../../schemas/bedrock-vc-workflow.js';
import {checkAccessToken} from '@bedrock/oauth2-verifier';
import {compile} from '@bedrock/validation';
import {ExchangeProcessor} from '../ExchangeProcessor.js';
import {getStepAuthorizationRequest} from './oid4vp.js';
import {verifyDidProofJwt} from '../verify.js';

const {util: {BedrockError}} = bedrock;

const PRE_AUTH_GRANT_TYPE =
  'urn:ietf:params:oauth:grant-type:pre-authorized_code';

const VALIDATORS = {
  authorizationDetails: null
};

bedrock.events.on('bedrock.init', () => {
  // create validators for x-www-form-urlencoded parsed data
  VALIDATORS.authorizationDetails = compile({
    schema: authorizationDetailsSchema()
  });
});

export async function getAuthorizationServerConfig({req}) {
  // note that technically, we should not need to serve any credential
  // issuer metadata, but we do for backwards compatibility purposes as
  // previous versions of OID4VCI required it
  return getCredentialIssuerConfig({req});
}

export async function getCredentialIssuerConfig({req}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  const {exchange} = exchangeRecord;
  _assertOID4VCISupported({exchange});

  // use exchange processor get current step of the exchange
  const exchangeProcessor = new ExchangeProcessor({workflow, exchangeRecord});
  const step = await exchangeProcessor.getStep();

  // fetch credential configurations for the step
  const credential_configurations_supported =
    _getSupportedCredentialConfigurations({workflow, exchange, step});

  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  return {
    authorization_details_types_supported: ['openid_credential'],
    batch_credential_endpoint: `${exchangeId}/openid/batch_credential`,
    credential_configurations_supported,
    credential_endpoint: `${exchangeId}/openid/credential`,
    credential_issuer: exchangeId,
    issuer: exchangeId,
    jwks_uri: `${exchangeId}/openid/jwks`,
    'pre-authorized_grant_anonymous_access_supported': true,
    nonce_endpoint: `${exchangeId}/openid/nonce`,
    token_endpoint: `${exchangeId}/openid/token`
  };
}

export async function getCredentialOffer({req}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  const {exchange} = exchangeRecord;
  _assertOID4VCISupported({exchange});

  // start building OID4VCI credential offer
  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  const offer = {
    credential_issuer: exchangeId,
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': exchange.openId.preAuthorizedCode
      }
    }
  };

  // use exchange processor get current step of the exchange
  const exchangeProcessor = new ExchangeProcessor({workflow, exchangeRecord});
  const step = await exchangeProcessor.getStep();

  // fetch credential configurations for the step
  const credential_configurations_supported =
    _getSupportedCredentialConfigurations({workflow, exchange, step});

  // offer all configuration IDs and support both spec version ID-1 with
  // `credentials` and draft 13 with `credential_configuration_ids`
  const configurationIds = Object.keys(credential_configurations_supported);
  offer.credentials = configurationIds;
  offer.credential_configuration_ids = configurationIds;

  return offer;
}

export async function getJwks({req}) {
  const {exchange} = await req.getExchange();
  _assertOID4VCISupported({exchange});
  return [exchange.openId.oauth2.keyPair.publicKeyJwk];
}

export function getOID4VCIProtocols({workflow, exchange}) {
  if(!supportsOID4VCI({exchange})) {
    return {};
  }
  // OID4VCI supported; add credential offer URL
  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  const searchParams = new URLSearchParams();
  const uri = `${exchangeId}/openid/credential-offer`;
  searchParams.set('credential_offer_uri', uri);
  return {OID4VCI: `openid-credential-offer://?${searchParams}`};
}

export async function initExchange({workflow, exchange} = {}) {
  if(!supportsOID4VCI({exchange})) {
    return;
  }

  // either issuer instances or a single issuer zcap be given if
  // any expected credential requests are given
  const {expectedCredentialRequests} = exchange.openId;
  if(expectedCredentialRequests &&
    !(workflow.issuerInstances || workflow.zcaps.issue)) {
    throw new BedrockError(
      'Credential requests are not supported by this workflow.', {
        name: 'DataError',
        details: {httpStatusCode: 400, public: true}
      });
  }
}

export async function processAccessTokenRequest({req}) {
  // parse `authorization_details` from request
  let authorizationDetails;
  if(req.body.authorization_details) {
    authorizationDetails = JSON.parse(req.body.authorization_details);
    _validate(VALIDATORS.authorizationDetails, authorizationDetails);
  }

  // check exchange
  const exchangeRecord = await req.getExchange();
  const {exchange} = exchangeRecord;
  _assertOID4VCISupported({exchange});

  /* Examples of types of token requests:
  pre-authz code:
  grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
  &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
  &tx_code=493536
  &authorization_details=<URI-component-encoded JSON array>

  authz code:
  grant_type=authorization_code
  &code=SplxlOBeZQQYbYS6WxSbIA
  &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  &redirect_uri=https%3A%2F%2FWallet.example.org%2Fcb */

  const {config: workflow} = req.serviceObject;

  const {
    grant_type: grantType,
    'pre-authorized_code': preAuthorizedCode
  } = req.body;

  if(grantType !== PRE_AUTH_GRANT_TYPE) {
    // unsupported grant type
    // FIXME: throw proper oauth2 formatted error
    throw new Error('Unsupported grant type.');
  }

  // validate grant type
  const {openId: {preAuthorizedCode: expectedCode}} = exchange;
  if(expectedCode) {
    // ensure expected pre-authz code matches
    if(!timingSafeEqual(
      Buffer.from(expectedCode, 'utf8'),
      Buffer.from(preAuthorizedCode, 'utf8'))) {
      // FIXME: throw proper oauth2 formatted error
      throw new Error('invalid pre-authorized-code or user pin');
    }
  }

  // process exchange to generate supported credential requests
  let supportedCredentialRequestsStored;
  let supportedCredentialRequests;
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    async prepareStep({exchange, step}) {
      // do not generate any VPR yet
      step.verifiablePresentationRequest = undefined;

      // if not generated, generate supported credential requests and store
      // in step results
      const stepResults = exchange.variables.results[exchange.step];
      supportedCredentialRequests = stepResults
        ?.openId?.supportedCredentialRequests;
      if(supportedCredentialRequests) {
        supportedCredentialRequestsStored = true;
      } else {
        supportedCredentialRequests = _createSupportedCredentialRequests({
          workflow, exchange, step
        });
        exchange.variables.results[exchange.step] = {
          ...exchange.variables.results[exchange.step],
          openId: {
            ...exchange.variables.results[exchange.step]?.openId,
            supportedCredentialRequests
          }
        };
      }
    },
    inputRequired({step}) {
      // if the supported credential requests haven't been stored in the
      // step result yet, then input is not required but issuance needs to
      // be disabled to allow them to be stored and then the step reprocessed
      if(!supportedCredentialRequestsStored) {
        step.issueRequests = [];
        step.verifiablePresentation = undefined;
        return false;
      }
      // requests stored and input is now required via credential endpoint
      return true;
    },
    isStepComplete() {
      // getting an access token never completes the step
      return false;
    }
  });
  await exchangeProcessor.process();

  // process `authorizationDetails` request, if any, to create token
  // authorization details
  let tokenAuthorizationDetails;
  if(authorizationDetails) {
    // create map of unprocessed credential configuration ID => credential IDs
    const idMap = new Map();
    for(const request of supportedCredentialRequests) {
      if(!supportedCredentialRequests.processed) {
        let credentialIds = idMap.get(request.credentialConfigurationId);
        if(!credentialIds) {
          credentialIds = [];
          idMap.set(request.credentialConfigurationId, credentialIds);
        }
        credentialIds.push(request.credentialIdentifier);
      }
    }

    // populate token authorization details by matching each requested
    // credential configuration ID with its credential IDs
    const requestedIds = new Set(authorizationDetails.map(
      detail => detail.credential_configuration_id));
    tokenAuthorizationDetails = [];
    for(const credentialConfigurationId of requestedIds) {
      const credentialIds = idMap.get(credentialConfigurationId);
      if(credentialIds) {
        tokenAuthorizationDetails.push({
          type: 'openid_credential',
          credential_configuration_id: credentialConfigurationId,
          credential_identifiers: credentialIds
        });
      }
    }
  }

  // create access token
  const {accessToken, ttl} = await _createExchangeAccessToken({
    workflow, exchangeRecord
  });

  // return token info
  const tokenInfo = {
    access_token: accessToken,
    token_type: 'bearer',
    expires_in: ttl
  };
  if(tokenAuthorizationDetails) {
    tokenInfo.authorization_details = tokenAuthorizationDetails;
  }
  return tokenInfo;
}

export async function processCredentialRequests({req, res, isBatchRequest}) {
  const {config: workflow} = req.serviceObject;
  const exchangeRecord = await req.getExchange();
  const {exchange} = exchangeRecord;
  _assertOID4VCISupported({exchange});

  // ensure oauth2 access token is valid
  await _checkAuthz({req, workflow, exchange});

  // process exchange and capture values to return
  let didProofRequired = false;
  let format;
  let issueResult;
  let matchingCredentialIdentifiers;
  let supportedCredentialRequests;
  const exchangeProcessor = new ExchangeProcessor({
    workflow, exchangeRecord,
    async prepareStep({exchange, step}) {
      // get `supportedCredentialRequests` from step results
      supportedCredentialRequests = await _getSupportedCredentialRequests({
        exchangeProcessor, workflow, exchange, step
      });

      // if the issue result has been generated, return early and allow
      // `isInputRequired()` to handle further processing
      if(issueResult) {
        return;
      }

      // fetch credential configurations for the step
      const supportedCredentialConfigurations =
        _getSupportedCredentialConfigurations({workflow, exchange, step});

      // get credential requests (only more than one w/`isBatchRequest=true`)
      let credentialRequests = isBatchRequest ?
        req.body.credential_requests : [req.body];

      // normalize draft 13 requests
      if(isBatchRequest || req.body?.format) {
        credentialRequests = draft13.normalizeCredentialRequestsToVersion1({
          credentialRequests,
          supportedCredentialConfigurations
        });
        // set `format`
        const configuration = supportedCredentialConfigurations[
          credentialRequests[0].credential_configuration_id];
        ({format} = configuration);
      }

      // map each credential request to an appropriate supported credential
      // request; for OID4VCI 1.0+ clients, there will be a single request
      // with a `credential_identifier`; for draft 13, one or more requests,
      // each with `credential_configuration_id` set will be present and
      // these must map to *every* matching supported request
      const unprocessed = supportedCredentialRequests.filter(r => !r.processed);
      matchingCredentialIdentifiers = new Set();
      for(const credentialRequest of credentialRequests) {
        const {
          credential_identifier, credential_configuration_id
        } = credentialRequest;

        // OID4VCI 1.0+ case
        if(credentialRequest.credential_identifier) {
          const match = unprocessed.find(
            r => r.credentialIdentifier === credential_identifier);
          if(match) {
            matchingCredentialIdentifiers.add(credential_identifier);
          }
          break;
        }

        // draft 13 case
        unprocessed.filter(
          r => r.credentialConfigurationId === credential_configuration_id)
          .forEach(
            r => matchingCredentialIdentifiers.add(r.credentialIdentifier));
      }

      // handle no match case
      if(matchingCredentialIdentifiers.size === 0) {
        throw new BedrockError(
          'The requested credential(s) have already been delivered.', {
            name: 'NotAllowedError',
            details: {httpStatusCode: 403, public: true}
          });
      }

      const {jwtDidProofRequest} = step;

      // check to see if step supports OID4VP during OID4VCI
      if(step.openId) {
        // Note: either OID4VCI 1.1+ w/IAE (interactive authz endpoint) or
        // OID4VCI-1.0/draft13+OID4VP will have received VP results which will
        // be stored with this step; OID4VCI 1.0- does not have IAE so if this
        // call is made, presume such a client and return an error with the
        // OID4VP request, OID4VCI 1.1+ clients will know to use IAE instead

        // if there is no verified presentation yet, request one
        const {results} = exchange.variables;
        if(!results[exchange.step]?.verifyPresentationResults?.verified) {
          // note: only the "default" `clientProfileId` is supported at this
          // time because there isn't presently a defined way to specify
          // alternatives
          const clientProfileId = step.openId.clientProfiles ?
            'default' : undefined;
          // get authorization request
          const {authorizationRequest} = await getStepAuthorizationRequest({
            workflow, exchange, step, clientProfileId
          });
          return _requestOID4VP({authorizationRequest, res});
        }
        // otherwise drop down below to complete exchange...
      } else if(jwtDidProofRequest) {
        // handle OID4VCI specialized JWT DID Proof request...

        // `proof` must be in every credential request; if any request is
        // missing `proof` then request a DID proof
        if(credentialRequests.some(cr => !cr.proofs?.jwt)) {
          didProofRequired = true;
          return _requestDidProof({res, exchangeRecord});
        }

        // verify every DID proof and get resulting DIDs
        const results = await Promise.all(
          credentialRequests.map(async cr => {
            // FIXME: do not support more than one proof at this time
            const {proofs: {jwt: [jwt]}} = cr;
            const {did} = await verifyDidProofJwt({workflow, exchange, jwt});
            return did;
          }));
        // require `did` to be the same for every proof
        // FIXME: determine if this needs to be more flexible
        const did = results[0];
        if(results.some(d => did !== d)) {
          // FIXME: improve error
          throw new Error('every DID must be the same');
        }
        // store did results in variables associated with current step
        exchange.variables.results[exchange.step] = {
          ...exchange.variables.results[exchange.step],
          // common use case of DID Authentication; provide `did` for ease
          // of use in templates
          did
        };
      }
    },
    inputRequired({exchange, step}) {
      // if issue result has been generated...
      if(issueResult) {
        // reapply any stored credentials in case the exchange was concurrently
        // updated by another credential request call
        const {storedCredentials, matchingCredentialIdentifiers} = issueResult;
        if(issueResult.storedCredentials) {
          for(const stored of storedCredentials) {
            setVariable({
              variables: exchange.variables,
              name: stored.name,
              value: stored.value
            });
          }
        }
        // mark all matching `supportedCredentialRequests` as processed
        supportedCredentialRequests
          .filter(r =>
            matchingCredentialIdentifiers.has(r.credentialIdentifier))
          .forEach(r => r.processed = true);

        // do not generate any VPR or issue anything else, additional requests
        // must be made when using OID4VCI
        step.verifiablePresentationRequest = undefined;
        step.verifiablePresentation = undefined;
        step.issueRequests = [];

        // if any supported credential requests has not yet been processed,
        // then input is required in the form of another credential request
        return supportedCredentialRequests.some(r => !r.processed);
      }

      // otherwise, input is required if:
      // 1. a `jwtDidProofRequest` is required and hasn't been provided
      // 2. OID4VP is enabled and no OID4VP result has been stored yet
      return didProofRequired || (step.openId && !exchange.variables
        .results[exchange.step]?.openId?.authorizationRequest);
    },
    async issue({
      workflow, exchange, step, issueRequestsParams,
      verifiablePresentation
    }) {
      // issue result already generated, skip
      if(issueResult) {
        return issueResult;
      }
      // filter `supportedCredentialRequests` using matching credential
      // identifiers and map to only those `issueRequestsParams` that are to
      // be issued now
      issueRequestsParams = supportedCredentialRequests
        .filter(r => matchingCredentialIdentifiers.has(r.credentialIdentifier))
        .map(r => issueRequestsParams[r.issueRequestsParamsIndex])
        .filter(p => !!p);

      // perform issuance and capture result to return it to the client and
      // to prevent subsequent reissuance if a concurrent request is made for
      // other credentials
      issueResult = await defaultIssue({
        workflow, exchange, step, issueRequestsParams,
        verifiablePresentation, format
      });
      issueResult.matchingCredentialIdentifiers =
        matchingCredentialIdentifiers;
      return issueResult;
    },
    isStepComplete() {
      // step complete if all supported credential requests have been processed
      return supportedCredentialRequests.every(r => r.processed);
    }
  });
  // always allow retrying with OID4VCI; issued VCs will be stored in memory
  // and an assumption is made that workflow steps WILL NOT change issue
  // requests in a step once `supportedCredentialRequests` has been created
  exchangeProcessor.canRetry = true;
  await exchangeProcessor.process();
  // use `issueResult` response
  const response = issueResult?.response;
  if(!response?.verifiablePresentation) {
    return null;
  }
  return {response, format};
}

export function supportsOID4VCI({exchange}) {
  // FIXME: might want something more explicit/or check in `workflow` and not
  // exchange
  return exchange.openId?.preAuthorizedCode !== undefined;
}

function _assertOID4VCISupported({exchange}) {
  if(!supportsOID4VCI({exchange})) {
    throw new BedrockError('OID4VCI is not supported by this exchange.', {
      name: 'NotSupportedError',
      details: {httpStatusCode: 400, public: true}
    });
  }
}

async function _checkAuthz({req, workflow, exchange}) {
  // optional oauth2 options
  const {oauth2} = exchange.openId;
  const {maxClockSkew} = oauth2;

  // audience is always the `exchangeId` and cannot be configured; this
  // prevents attacks where access tokens could otherwise be generated
  // if the AS keys were compromised; the `exchangeId` must also be known
  const exchangeId = `${workflow.id}/exchanges/${req.params.exchangeId}`;
  const audience = exchangeId;

  // `issuerConfigUrl` is always based off of the `exchangeId` as well
  const parsedIssuer = new URL(exchangeId);
  const issuerConfigUrl =
    `${parsedIssuer.origin}/.well-known/oauth-authorization-server` +
    parsedIssuer.pathname;

  // FIXME: `allowedAlgorithms` should be computed from `oauth2.keyPair`
  // const allowedAlgorithms =

  // ensure access token is valid
  await checkAccessToken({req, issuerConfigUrl, maxClockSkew, audience});
}

async function _createExchangeAccessToken({workflow, exchangeRecord}) {
  // FIXME: set `exp` to max of 15 minutes / configured max minutes
  const expires = exchangeRecord.meta.expires;
  const exp = Math.floor(expires.getTime() / 1000);

  // create access token
  const {exchange} = exchangeRecord;
  const {openId: {oauth2: {keyPair: {privateKeyJwk}}}} = exchange;
  const exchangeId = `${workflow.id}/exchanges/${exchange.id}`;
  const {accessToken, ttl} = await _createOAuth2AccessToken({
    privateKeyJwk, audience: exchangeId, action: 'write', target: exchangeId,
    exp, iss: exchangeId
  });
  return {accessToken, ttl};
}

function _createSupportedCredentialRequests({
  workflow, exchange, step
}) {
  let supportedCredentialRequests;

  const issueRequestsParams = getIssueRequestsParams({
    workflow, exchange, step
  });

  // determine if issue request params is legacy or modern
  const isDraft13 = issueRequestsParams.some(
    p => !p?.oid4vci?.credentialConfigurationId);
  if(isDraft13) {
    supportedCredentialRequests =
      draft13.createSupportedCredentialRequests({
        workflow, exchange, issueRequestsParams
      });
  } else {
    supportedCredentialRequests = [];
    for(const [index, params] of issueRequestsParams.entries()) {
      const {credentialConfigurationId} = params.oid4vci;
      supportedCredentialRequests.push({
        credentialConfigurationId,
        credentialIdentifier: uuid(),
        issueRequestsParamsIndex: index,
        processed: false
      });
    }
  }

  return supportedCredentialRequests;
}

async function _createOAuth2AccessToken({
  privateKeyJwk, audience, action, target, exp, iss, nbf, typ = 'at+jwt'
}) {
  const alg = _getAlgFromPrivateKey({privateKeyJwk});
  const scope = `${action}:${target}`;
  const builder = new SignJWT({scope})
    .setProtectedHeader({alg, typ})
    .setIssuer(iss)
    .setAudience(audience);
  let ttl;
  if(exp !== undefined) {
    builder.setExpirationTime(exp);
    ttl = Math.max(0, exp - Math.floor(Date.now() / 1000));
  } else {
    // default to 15 minute expiration time
    builder.setExpirationTime('15m');
    ttl = Math.floor(Date.now() / 1000) + 15 * 60;
  }
  if(nbf !== undefined) {
    builder.setNotBefore(nbf);
  }
  const key = await importJWK({...privateKeyJwk, alg});
  const accessToken = await builder.sign(key);
  return {accessToken, ttl};
}

function _getAlgFromPrivateKey({privateKeyJwk}) {
  if(privateKeyJwk.alg) {
    return privateKeyJwk.alg;
  }
  if(privateKeyJwk.kty === 'EC' && privateKeyJwk.crv) {
    if(privateKeyJwk.crv.startsWith('P-')) {
      return `ES${privateKeyJwk.crv.slice(2)}`;
    }
    if(privateKeyJwk.crv === 'secp256k1') {
      return 'ES256K';
    }
  }
  if(privateKeyJwk.kty === 'OKP' && privateKeyJwk.crv?.startsWith('Ed')) {
    return 'EdDSA';
  }
  if(privateKeyJwk.kty === 'RSA') {
    return 'PS256';
  }
  return 'invalid';
}

function _getSupportedCredentialConfigurations({workflow, exchange, step}) {
  // get all OID4VCI credential configuration IDs from issue requests in step
  const issueRequestsParams = getIssueRequestsParams({
    workflow, exchange, step
  });
  const credentialConfigurationIds = new Set([
    ...issueRequestsParams
      .map(p => p?.oid4vci?.credentialConfigurationId)
      .filter(id => id !== undefined)
  ]);

  // get all issuer instances for the workflow
  const issuerInstances = getWorkflowIssuerInstances({workflow});

  // in modern workflows, credential configuration IDs are explicitly provided
  if(credentialConfigurationIds.size > 0) {
    // map each ID to a credential configuration in an issuer instance
    const supported = new Map();
    for(const id of credentialConfigurationIds) {
      const match = issuerInstances.find(
        ii => ii.oid4vci?.supportedCredentialConfigurations?.[id]);
      if(match) {
        supported.set(id, match.oid4vci.supportedCredentialConfigurations[id]);
      }
    }
    return Object.fromEntries(supported.entries());
  }

  // no explicit IDs; create legacy supported credential configurations
  return draft13.createSupportedCredentialConfigurations({
    exchange, issuerInstances
  });
}

async function _getSupportedCredentialRequests({
  exchangeProcessor, workflow, exchange, step
}) {
  // get `supportedCredentialRequests` from step results
  const stepResults = exchange.variables.results[exchange.step];
  let supportedCredentialRequests = stepResults
    ?.openId?.supportedCredentialRequests;

  // if `supportedCredentialRequests` is not set, create it; this can only
  // happen in the degenerate case that an older version of the software
  // provided the access token to the client
  if(!supportedCredentialRequests) {
    supportedCredentialRequests = _createSupportedCredentialRequests({
      workflow, exchange, step
    });
    exchange.variables.results[exchange.step] = {
      ...exchange.variables.results[exchange.step],
      openId: {
        ...exchange.variables.results[exchange.step]?.openId,
        supportedCredentialRequests
      }
    };
    // explicitly update exchange to ensure `supportedCredentialRequests`
    // are committed
    await exchangeProcessor.updateExchange({step});
  }

  return supportedCredentialRequests;
}

async function _requestDidProof({res, exchangeRecord}) {
  /* `9.4 Credential Issuer-provided nonce` allows the credential
  issuer infrastructure to provide the nonce via an error:

  HTTP/1.1 400 Bad Request
  Content-Type: application/json
  Cache-Control: no-store

  {
    "error": "invalid_or_missing_proof"
    "error_description":
        "Credential issuer requires proof element in Credential Request"
    "c_nonce": "8YE9hCnyV2",
    "c_nonce_expires_in": 86400
  }*/

  /* OID4VCI exchanges themselves are not replayable and single-step, so the
  challenge to be signed is just the exchange ID itself. An exchange cannot
  be reused and neither can a challenge. */
  const {exchange, meta: {expires}} = exchangeRecord;
  const ttl = Math.floor((expires.getTime() - Date.now()) / 1000);

  _sendOID4Error({
    res,
    error: 'invalid_proof',
    description:
      'Credential issuer requires proof element in Credential Request',
    // use exchange ID
    c_nonce: exchange.id,
    // use exchange expiration period
    c_nonce_expires_in: ttl
  });
}

async function _requestOID4VP({authorizationRequest, res}) {
  /* Error thrown when OID4VP is required to complete OID4VCI:

  HTTP/1.1 400 Bad Request
  Content-Type: application/json
  Cache-Control: no-store

  {
    "error": "presentation_required"
    "error_description":
      "Credential issuer requires presentation before Credential Request"
    "authorization_request": {
      "response_type": "vp_token",
      "presentation_definition": {
        id: "<urn:uuid>",
        input_descriptors: {...}
      },
      "response_mode": "direct_post"
    }
  }*/

  /* OID4VCI exchanges themselves are not replayable and single-step, so the
  challenge to be signed is just the exchange ID itself. An exchange cannot
  be reused and neither can a challenge. */

  _sendOID4Error({
    res,
    error: 'presentation_required',
    description:
      'Credential issuer requires presentation before Credential Request',
    authorization_request: authorizationRequest
  });
}

function _sendOID4Error({res, error, description, status = 400, ...rest}) {
  res.status(status).json({
    error,
    error_description: description,
    ...rest
  });
}

function _validate(validator, data) {
  const result = validator(data);
  if(!result.valid) {
    throw result.error;
  }
}
