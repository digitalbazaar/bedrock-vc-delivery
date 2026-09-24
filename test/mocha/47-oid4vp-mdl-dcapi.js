/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */
import * as helpers from './helpers.js';
import * as mdlUtils from './mdlUtils.js';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {randomUUID as uuid} from 'node:crypto';

const {baseUrl} = mockData;
const {getAuthorizationRequest} = oid4vp;

const PROTOCOL_NAMES = [
  'OID4VP',
  '18013-7-Annex-C',
  '18013-7-Annex-D'
];

describe('DC-API presentation', () => {
  const leafDnsName = 'mdl.reader.example';
  let capabilityAgent;
  let deviceKeyPair;
  // `mdocCertChain` is for verifying the mDL issuer's signature
  let mdocCertChain;
  let mdoc;
  // `authorizationRequestPrivateKeyJwk`, `x5c`, and `trustedCertificates` are
  // for verifying the mDL reader's signature, they are not for mDL issuers
  let authorizationRequestPrivateKeyJwk;
  let x5c;
  let trustedCertificates;
  let signAuthorizationRequestRefId;
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    // add `mdoc` config to verifier config options
    const caStoreId = `urn:mdoc-ca-store:${uuid()}`;
    const verifierOptions = {
      verifyOptions: {
        mdoc: {
          caStores: [caStoreId]
        }
      }
    };
    const deps = await helpers.provisionDependencies({verifierOptions});
    const {
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent, mdocCertChain} = deps);

    const zcaps = {
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };

    // create OID4VP authz request signing params
    const authzRequestSigningParams = await helpers
      .createWorkflowOid4vpAuthzRequestSigningParams({
        capabilityAgent, leafConfig: {dnsName: leafDnsName},
        // note: set to `false` to use zcap for authz signing private key
        // instead of a `privateKeyJwk`
        returnPrivateKeyJwk: true
      });
    ({
      authorizationRequestPrivateKeyJwk,
      x5c,
      trustedCertificates
    } = authzRequestSigningParams);

    // only present if `returnPrivateKeyJwk: false` above
    const {signAuthorizationRequestZcap} = authzRequestSigningParams;
    if(signAuthorizationRequestZcap) {
      signAuthorizationRequestRefId = `urn:uuid:${uuid()}`;
      zcaps[signAuthorizationRequestRefId] = signAuthorizationRequestZcap;
    }

    // create workflow instance w/ oauth2-based authz
    // require semantically-named workflow steps
    const steps = {
      myStep: {
        stepTemplate: {
          type: 'jsonata',
          template: _createStepTemplate({
            leafDnsName, x5c, signAuthorizationRequestRefId,
            authorizationRequestPrivateKeyJwk
          })
        }
      }
    };

    // set initial step
    const initialStep = 'myStep';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, steps, initialStep, oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;

    // issue mDL for presentation below...

    // get device key pair
    deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // issue an MDL
    const issuerPrivateJwk = mdocCertChain.leaf.subject.jwk;
    const issuerCertificate = mdocCertChain.leaf.pemCertificate;
    mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });
  });

  it('should pass', async () => {
    for(const protocolName of PROTOCOL_NAMES) {
      await _executeExchange({protocolName});
    }
  });

  async function _executeExchange({protocolName}) {
    // create an exchange
    const exchange = _createExchangeRequest();
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });

    const getTrustedCertificates = async () => trustedCertificates;

    // always fetch *all* possible authz requests to ensure a single button
    // DC API implementation would work by including all requests at once
    const authzRequestMap = new Map();
    for(const name of PROTOCOL_NAMES) {
      const profileName = encodeURIComponent(
        name === 'OID4VP' ? 'default' : name);
      const authzReqUrl =
        `${exchangeId}/openid/clients/${profileName}/authorization/request`;

      let oid4vpUrl;
      {
        // `openid4vp` URL would be:
        const searchParams = new URLSearchParams({
          client_id: `x509_san_dns:${leafDnsName}`,
          request_uri: authzReqUrl,
          request_uri_method: 'post'
        });
        oid4vpUrl = 'openid4vp://?' + searchParams.toString();

        // confirm oid4vp URL matches the one in `protocols`
        const protocolsUrl = `${exchangeId}/protocols`;
        const response = await httpClient.get(protocolsUrl, {agent});
        should.exist(response);
        should.exist(response.data);
        should.exist(response.data.protocols);
        should.exist(response.data.protocols.vcapi);
        response.data.protocols.vcapi.should.equal(exchangeId);
        should.exist(response.data.protocols[name]);
        response.data.protocols[name].should.equal(oid4vpUrl);
      }

      // get authorization request
      const {authorizationRequest} = await getAuthorizationRequest(
        {url: oid4vpUrl, getTrustedCertificates, agent});
      // client ID should be prefixed
      should.exist(authorizationRequest);
      should.exist(authorizationRequest.client_id.should.equal(
        `x509_san_dns:${leafDnsName}`
      ));
      // PE should be auto-generated
      should.exist(authorizationRequest.presentation_definition);
      authorizationRequest.presentation_definition.id.should.be.a('string');
      authorizationRequest.presentation_definition.input_descriptors.should.be
        .an('array');
      if(name === '18013-7-Annex-C') {
        authorizationRequest.response_mode.should.equal('dc_api');
      } else {
        authorizationRequest.response_mode.should.equal('dc_api.jwt');
      }
      authorizationRequest.nonce.should.be.a('string');
      authorizationRequest.client_metadata
        .vp_formats.should.include.keys(['mso_mdoc']);
      // ensure DCQL is set
      should.exist(authorizationRequest.dcql_query);

      // save authz request; would be included in a single DC API request
      authzRequestMap.set(name, {
        profileName,
        oid4vpUrl,
        authorizationRequest
      });
    }

    // choose `protocolName`-specific authz request for processing as the
    // DC API internals would
    const {authorizationRequest} = authzRequestMap.get(protocolName);

    // generate mdoc device response as VP...

    // select recipient public key for encryption
    const recipientPublicJwk = oid4vp.authzResponse.selectRecipientPublicJwk({
      authorizationRequest
    });

    let handover;
    if(authorizationRequest.response_mode === 'dc_api') {
      // create an mdoc Annex C handover
      handover = {
        type: 'dcapi',
        origin: `https://${leafDnsName}`,
        nonce: authorizationRequest.nonce,
        recipientPublicJwk
      };
    } else {
      // create an mdoc Annex D handover
      handover = {
        type: 'OpenID4VPDCAPIHandover',
        origin: `https://${leafDnsName}`,
        nonce: authorizationRequest.nonce,
        recipientPublicJwk
      };
    }

    // create mDL enveloped presentation
    const verifiablePresentation = await mdlUtils.createPresentation({
      presentationDefinition: authorizationRequest.presentation_definition,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // `vpToken` format depends on `response_mode`; response modes under test
    // here both use a base64url-encoded mdoc device response, but differ in
    // how it is wrapped
    const b64Mdoc = verifiablePresentation.id.slice(
      verifiablePresentation.id.indexOf(',') + 1);
    const b64UrlMDoc = Buffer.from(b64Mdoc, 'base64').toString('base64url');
    let vpToken;
    if(authorizationRequest.response_mode === 'dc_api') {
      // use base64url-encoded mdoc device response directly
      vpToken = b64UrlMDoc;
    } else {
      // default to a credential response object with a key identifying the
      // DCQL credential query and an array with a base64url-encoded mdoc
      // device response as its single element
      vpToken = {'mdl-id': [b64UrlMDoc]};
    }

    // get expected presentation response
    let expectedPresentation;
    {
      const deviceResponse = Buffer.from(b64UrlMDoc, 'base64url');
      expectedPresentation = await mdlUtils.verifyPresentation({
        deviceResponse, handover,
        trustedCertificates: [mdocCertChain.intermediate.pemCertificate]
      });
      should.exist(expectedPresentation);
    }

    // send authorization response
    const {result} = await oid4vp.sendAuthorizationResponse({
      vpToken,
      // hacky; `vpToken` media type is inaccurate when a DCQL response wrapper
      // encapsulates the base64url-encoded mdoc device response; this should
      // be fixed in `@digitalbazaar/oid4-client`, not here
      vpTokenMediaType: 'application/mdoc-vp-token',
      verifiablePresentation, authorizationRequest, agent,
      encryptionOptions: {
        mdoc: {handover},
        recipientPublicJwk
      }
    });
    should.exist(result);

    // exchange should be complete and contain the VP and open ID results
    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange.variables?.results?.myStep);
        should.exist(
          exchange.variables?.results?.myStep?.verifiablePresentation);
        exchange.variables.results.myStep.verifiablePresentation
          .should.deep.equal(expectedPresentation);
        should.exist(exchange.variables.results.myStep.openId);
        exchange.variables.results.myStep.openId.authorizationRequest
          .should.deep.equal(authorizationRequest);
      } catch(error) {
        err = error;
      }
      assertNoError(err);
    }
  }
});

function _createExchangeRequest() {
  return {
    // 15 minute expiry in seconds
    ttl: 60 * 15,
    // template variables
    variables: {}
  };
}

function _createClientProfile({
  protocolName, responseMode,
  leafDnsName, x5c,
  signAuthorizationRequestRefId, authorizationRequestPrivateKeyJwk
}) {
  return {
    // ensure each created authz request gets stored in a different variable
    createAuthorizationRequest: `/authorizationRequest/${protocolName}`,
    response_mode: responseMode,
    client_id: leafDnsName,
    client_id_scheme: 'x509_san_dns',
    // enable signed authz request
    client_metadata: {
      require_signed_request_object: true
    },
    expected_origins: [`https://${leafDnsName}`],
    authorizationRequestSigningParameters: {
      privateKeyJwk: authorizationRequestPrivateKeyJwk,
      x5c
    },
    dcql_query: {
      credentials: [{
        id: 'mdl-id',
        format: 'mso_mdoc',
        meta: {
          doctype_value: 'org.iso.18013.5.1.mDL'
        },
        claims: [{
          path: ['org.iso.18013.5.1', 'age_over_21'],
          intent_to_retain: false
        }]
      }]
    },
    protocolUrlParameters: {
      name: protocolName,
      scheme: 'openid4vp'
    },
    zcapReferenceIds: {
      signAuthorizationRequest: signAuthorizationRequestRefId
    }
  };
}

function _createStepTemplate({
  leafDnsName, x5c,
  signAuthorizationRequestRefId, authorizationRequestPrivateKeyJwk
}) {
  const templateObject = {
    createChallenge: true,
    verifiablePresentationRequest: {
      query: [{
        type: 'QueryByExample',
        group: 'vc',
        credentialQuery: {
          reason: 'You must be over 18 years old to use this service.',
          example: {
            '@context': [
              'https://www.w3.org/ns/credentials/v2',
              'https://w3id.org/vdl/v2'
            ],
            type: 'Iso18013DriversLicenseCredential',
            credentialSubject: {
              driversLicense: {
                age_over_18: true
              }
            }
          }
        }
      }, {
        type: 'QueryByExample',
        group: 'mdl',
        credentialQuery: {
          example: {
            'org.iso.18013.5.1': {
              age_over_21: ''
            }
          },
          acceptedEnvelopes: [{
            mediaType: 'application/mdoc',
            meta: {docType: 'org.iso.18013.5.1.mDL'}
          }]
        }
      }],
      domain: baseUrl
    },
    openId: {
      clientProfiles: {
        default: _createClientProfile({
          protocolName: 'OID4VP',
          responseMode: 'dc_api.jwt',
          leafDnsName, x5c,
          signAuthorizationRequestRefId, authorizationRequestPrivateKeyJwk
        }),
        '18013-7-Annex-C': _createClientProfile({
          protocolName: '18013-7-Annex-C',
          responseMode: 'dc_api',
          leafDnsName, x5c,
          signAuthorizationRequestRefId, authorizationRequestPrivateKeyJwk
        }),
        '18013-7-Annex-D': _createClientProfile({
          protocolName: '18013-7-Annex-D',
          responseMode: 'dc_api.jwt',
          leafDnsName, x5c,
          signAuthorizationRequestRefId, authorizationRequestPrivateKeyJwk
        })
      }
    }
  };
  return JSON.stringify(templateObject, null, 2);
}
