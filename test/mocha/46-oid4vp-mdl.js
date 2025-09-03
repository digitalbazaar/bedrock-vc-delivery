/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import * as mdlUtils from './mdlUtils.js';
import {agent} from '@bedrock/https-agent';
import {generateKeyPair} from './certUtils.js';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {randomUUID as uuid} from 'node:crypto';

const {baseUrl} = mockData;
const {getAuthorizationRequest} = oid4vp;

describe('exchange w/ OID4VP mDL presentation', () => {
  const leafDnsName = 'mdl.reader.example';
  let capabilityAgent;
  let deviceKeyPair;
  // `mdlCertChain` is for verifying the mDL issuer's signature
  let mdlCertChain;
  let mdoc;
  // `x5c` and `trustedCertificates` are for verifying the mDL
  // reader's signature
  let x5c;
  let trustedCertificates;
  let signAuthorizationRequestRefId;
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    // add `mdl` config to verifier config options
    const caStoreId = `urn:mdl-ca-store:${uuid()}`;
    const verifierOptions = {
      verifyOptions: {
        mdl: {
          caStores: [caStoreId]
        }
      }
    };
    const deps = await helpers.provisionDependencies({verifierOptions});
    const {
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent, mdlCertChain} = deps);

    // create OID4VP authz request signing params
    const authzRequestSigningParams = await helpers
      .createWorkflowOid4vpAuthzRequestSigningParams({
        capabilityAgent, leafConfig: {dnsName: leafDnsName}
      });
    ({
      x5c,
      trustedCertificates
    } = authzRequestSigningParams);
    const {signAuthorizationRequestZcap} = authzRequestSigningParams;

    // create workflow instance w/ oauth2-based authz
    signAuthorizationRequestRefId = `urn:uuid:${uuid()}`;
    const zcaps = {
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap,
      [signAuthorizationRequestRefId]: signAuthorizationRequestZcap
    };
    // require semantically-named workflow steps
    const steps = {
      myStep: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "createChallenge": true,
            "verifiablePresentationRequest": verifiablePresentationRequest,
            "openId": openId
          }`
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
    const issuerPrivateJwk = mdlCertChain.leaf.subject.jwk;
    const issuerCertificate = mdlCertChain.leaf.pemCertificate;
    mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });
  });

  it('should pass', async () => {
    // mDL presentation definition
    const presentationDefinition = {
      id: 'mdl-test-age-over-21',
      input_descriptors: [
        {
          id: 'org.iso.18013.5.1.mDL',
          format: {
            mso_mdoc: {
              alg: ['ES256']
            }
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                // eslint-disable-next-line quotes
                path: ["$['org.iso.18013.5.1']['age_over_21']"],
                intent_to_retain: false
              }
            ]
          }
        }
      ]
    };

    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        verifiablePresentationRequest: {
          query: [{
            type: 'QueryByExample',
            credentialQuery: [{
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
              },
              // allow mDL presentation
              acceptedEnvelopes: ['application/mdl-vp-token']
            }]
          }],
          domain: baseUrl
        },
        openId: {
          clientProfiles: {
            default: {
              createAuthorizationRequest: 'authorizationRequest',
              response_mode: 'direct_post.jwt',
              client_id: leafDnsName,
              client_id_scheme: 'x509_san_dns',
              // enable signed authz request
              client_metadata: {
                require_signed_request_object: true
              },
              authorizationRequestSigningParameters: {
                x5c
              },
              presentation_definition: presentationDefinition,
              protocolUrlParameters: {
                name: 'mdoc-openid4vp',
                scheme: 'mdoc-openid4vp'
              },
              zcapReferenceIds: {
                signAuthorizationRequest: signAuthorizationRequestRefId
              }
            }
          }
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });
    const authzReqUrl =
      `${exchangeId}/openid/clients/default/authorization/request`;

    const getTrustedCertificates = async () => trustedCertificates;

    // confirm oid4vp URL matches the one in `protocols`
    let authzRequestFromOid4vpUrl;
    {
      // `mdoc-openid4vp` URL would be:
      const searchParams = new URLSearchParams({
        client_id: leafDnsName,
        request_uri: authzReqUrl
      });
      const mdocUrl = 'mdoc-openid4vp://?' + searchParams.toString();

      const protocolsUrl = `${exchangeId}/protocols`;
      const response = await httpClient.get(protocolsUrl, {agent});
      should.exist(response);
      should.exist(response.data);
      should.exist(response.data.protocols);
      // FIXME: enable disabling `vcapi` in protocols?
      should.exist(response.data.protocols.vcapi);
      response.data.protocols.vcapi.should.equal(exchangeId);
      should.exist(response.data.protocols['mdoc-openid4vp']);
      response.data.protocols['mdoc-openid4vp'].should.equal(mdocUrl);

      ({
        authorizationRequest: authzRequestFromOid4vpUrl
      } = await getAuthorizationRequest({
        url: mdocUrl, getTrustedCertificates, agent
      }));
    }

    // get authorization request
    const {authorizationRequest} = await getAuthorizationRequest(
      {url: authzReqUrl, getTrustedCertificates, agent});

    should.exist(authorizationRequest);
    should.exist(authorizationRequest.presentation_definition);
    authorizationRequest.presentation_definition.id.should.be.a('string');
    authorizationRequest.presentation_definition.input_descriptors.should.be
      .an('array');
    authorizationRequest.response_mode.should.equal('direct_post.jwt');
    authorizationRequest.nonce.should.be.a('string');
    authorizationRequest.client_metadata
      .vp_formats.should.include.keys(['mso_mdoc']);
    // FIXME: add assertions for `authorizationRequest.presentation_definition`

    // ensure authz request matches the one from mdoc-oid4vp URL
    authzRequestFromOid4vpUrl.should.deep.equal(authorizationRequest);

    // generate VPR from authorization request
    const {verifiablePresentationRequest} = await oid4vp.toVpr(
      {authorizationRequest});

    // VPR should be the same as the one from the exchange, modulo changes
    // comply with OID4VP spec
    /*const expectedVpr = {
      query: [{
        type: 'QueryByExample',
        credentialQuery: [{
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
          },
          acceptedEnvelopes: ['application/mdl-vp-token']
        }]
      }],
      // OID4VP requires this to be the authz response URL
      domain: authorizationRequest.response_uri,
      // challenge should be set to authz nonce
      challenge: authorizationRequest.nonce
    };*/
    // FIXME: enable
    //verifiablePresentationRequest.should.deep.equal(expectedVpr);

    // generate mDL device response as VP...

    // create an MDL session transcript
    const {domain, challenge} = verifiablePresentationRequest;
    const sessionTranscript = {
      mdocGeneratedNonce: uuid(),
      clientId: authorizationRequest.client_id,
      responseUri: domain,
      verifierGeneratedNonce: challenge
    };

    // create mDL enveloped presentation
    const verifiablePresentation = await mdlUtils.createPresentation({
      presentationDefinition: authorizationRequest.presentation_definition,
      mdoc,
      sessionTranscript,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // vpToken is base64url-encoded mDL device response
    const vpToken = verifiablePresentation.id.slice(
      verifiablePresentation.id.indexOf(',') + 1);

    // get expected presentation response
    let expectedPresentation;
    {
      const deviceResponse = Buffer.from(vpToken, 'base64url');
      expectedPresentation = await mdlUtils.verifyPresentation({
        deviceResponse, sessionTranscript,
        trustedCertificates: [mdlCertChain.intermediate.pemCertificate]
      });
    }

    // send authorization response
    // FIXME: auto-generate proper presentation submission
    const presentationSubmission = {
      id: 'ex:example',
      definition_id: 'ex:definition',
      descriptor_map: [{
        id: 'org.iso.18013.5.1.mDL',
        format: 'mso_mdoc',
        path: '$'
      }]
    };
    const {result} = await oid4vp.sendAuthorizationResponse({
      vpToken, verifiablePresentation, authorizationRequest, agent,
      presentationSubmission,
      encryptionOptions: {
        mdl: {
          sessionTranscript
        }
      }
    });
    // should be only an optional `redirect_uri` in the response
    should.exist(result);
    //should.exist(result.redirect_uri);

    // exchange should be complete and contain the VP and open ID results
    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.myStep);
        should.exist(
          exchange?.variables?.results?.myStep?.verifiablePresentation);
        exchange.variables.results.myStep.verifiablePresentation
          .should.deep.equal(expectedPresentation);
        should.exist(exchange.variables.results.myStep.openId);
        exchange.variables.results.myStep.openId.authorizationRequest
          .should.deep.equal(authorizationRequest);
        exchange.variables.results.myStep.openId.presentationSubmission
          .should.deep.equal(presentationSubmission);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });

  it('should fail w/invalid device signature', async () => {
    // mDL presentation definition
    const presentationDefinition = {
      id: 'mdl-test-age-over-21',
      input_descriptors: [
        {
          id: 'org.iso.18013.5.1.mDL',
          format: {
            mso_mdoc: {
              alg: ['ES256']
            }
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                // eslint-disable-next-line quotes
                path: ["$['org.iso.18013.5.1']['age_over_21']"],
                intent_to_retain: false
              }
            ]
          }
        }
      ]
    };

    // create an exchange with appropriate variables for the step template
    const exchange = {
      // 15 minute expiry in seconds
      ttl: 60 * 15,
      // template variables
      variables: {
        verifiablePresentationRequest: {
          query: [{
            type: 'QueryByExample',
            credentialQuery: [{
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
              },
              // allow mDL presentation
              acceptedEnvelopes: ['application/mdl-vp-token']
            }]
          }],
          domain: baseUrl
        },
        openId: {
          clientProfiles: {
            default: {
              createAuthorizationRequest: 'authorizationRequest',
              response_mode: 'direct_post.jwt',
              client_id: leafDnsName,
              client_id_scheme: 'x509_san_dns',
              // enable signed authz request
              client_metadata: {
                require_signed_request_object: true
              },
              authorizationRequestSigningParameters: {
                x5c
              },
              presentation_definition: presentationDefinition,
              protocolUrlParameters: {
                name: 'mdoc-openid4vp',
                scheme: 'mdoc-openid4vp'
              },
              zcapReferenceIds: {
                signAuthorizationRequest: signAuthorizationRequestRefId
              }
            }
          }
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });
    const authzReqUrl =
      `${exchangeId}/openid/clients/default/authorization/request`;

    const getTrustedCertificates = async () => trustedCertificates;

    // confirm oid4vp URL matches the one in `protocols`
    let authzRequestFromOid4vpUrl;
    {
      // `mdoc-openid4vp` URL would be:
      const searchParams = new URLSearchParams({
        client_id: leafDnsName,
        request_uri: authzReqUrl
      });
      const mdocUrl = 'mdoc-openid4vp://?' + searchParams.toString();

      const protocolsUrl = `${exchangeId}/protocols`;
      const response = await httpClient.get(protocolsUrl, {agent});
      should.exist(response);
      should.exist(response.data);
      should.exist(response.data.protocols);
      // FIXME: enable disabling `vcapi` in protocols?
      should.exist(response.data.protocols.vcapi);
      response.data.protocols.vcapi.should.equal(exchangeId);
      should.exist(response.data.protocols['mdoc-openid4vp']);
      response.data.protocols['mdoc-openid4vp'].should.equal(mdocUrl);

      ({
        authorizationRequest: authzRequestFromOid4vpUrl
      } = await getAuthorizationRequest({
        url: mdocUrl, getTrustedCertificates, agent
      }));
    }

    // get authorization request
    const {authorizationRequest} = await getAuthorizationRequest(
      {url: authzReqUrl, getTrustedCertificates, agent});

    should.exist(authorizationRequest);
    should.exist(authorizationRequest.presentation_definition);
    authorizationRequest.presentation_definition.id.should.be.a('string');
    authorizationRequest.presentation_definition.input_descriptors.should.be
      .an('array');
    authorizationRequest.response_mode.should.equal('direct_post.jwt');
    authorizationRequest.nonce.should.be.a('string');
    authorizationRequest.client_metadata
      .vp_formats.should.include.keys(['mso_mdoc']);
    // FIXME: add assertions for `authorizationRequest.presentation_definition`

    // ensure authz request matches the one from mdoc-oid4vp URL
    authzRequestFromOid4vpUrl.should.deep.equal(authorizationRequest);

    // generate VPR from authorization request
    const {verifiablePresentationRequest} = await oid4vp.toVpr(
      {authorizationRequest});

    // VPR should be the same as the one from the exchange, modulo changes
    // comply with OID4VP spec
    /*const expectedVpr = {
      query: [{
        type: 'QueryByExample',
        credentialQuery: [{
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
          },
          acceptedEnvelopes: ['application/mdl-vp-token']
        }]
      }],
      // OID4VP requires this to be the authz response URL
      domain: authorizationRequest.response_uri,
      // challenge should be set to authz nonce
      challenge: authorizationRequest.nonce
    };*/
    // FIXME: enable
    //verifiablePresentationRequest.should.deep.equal(expectedVpr);

    // generate mDL device response as VP...

    // create an MDL session transcript
    const {domain, challenge} = verifiablePresentationRequest;
    const sessionTranscript = {
      mdocGeneratedNonce: uuid(),
      clientId: authorizationRequest.client_id,
      responseUri: domain,
      verifierGeneratedNonce: challenge
    };

    // generate a different JWK to sign with so that the signature will NOT
    // match
    const {jwk: otherDevicePrivateJwk} = await generateKeyPair();

    // create MDL enveloped presentation
    const verifiablePresentation = await mdlUtils.createPresentation({
      presentationDefinition: authorizationRequest.presentation_definition,
      mdoc,
      sessionTranscript,
      devicePrivateJwk: otherDevicePrivateJwk
    });

    // vpToken is base64url-encoded mDL device response
    const vpToken = verifiablePresentation.id.slice(
      verifiablePresentation.id.indexOf(',') + 1);

    // get expected presentation response
    {
      const deviceResponse = Buffer.from(vpToken, 'base64url');
      await mdlUtils.verifyPresentation({
        deviceResponse, sessionTranscript,
        trustedCertificates: [mdlCertChain.intermediate.pemCertificate]
      });
    }

    // send authorization response
    // FIXME: auto-generate proper presentation submission
    const presentationSubmission = {
      id: 'ex:example',
      definition_id: 'ex:definition',
      descriptor_map: [{
        id: 'org.iso.18013.5.1.mDL',
        format: 'mso_mdoc',
        path: '$'
      }]
    };
    {
      let err;
      try {
        await oid4vp.sendAuthorizationResponse({
          vpToken, verifiablePresentation, authorizationRequest, agent,
          presentationSubmission,
          encryptionOptions: {
            mdl: {
              sessionTranscript
            }
          }
        });
      } catch(error) {
        err = error;
      }
      should.exist(err);
      err.message.should.include('authorization response: Verification error');
    }

    // exchange should NOT be complete and should have a `lastError`
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('active');
        should.exist(exchange.lastError);
        exchange.lastError.name.should.equal('DataError');
        exchange.lastError.message.should.include('Verification error');
        should.exist(exchange.lastError.details?.errors);
        exchange.lastError.details.errors[0].name.should.equal('MDLError');
        exchange.lastError.details.errors[0].message.should.include(
          'Device signature must be valid');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });
});
