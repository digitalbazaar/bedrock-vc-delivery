/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import * as mdlUtils from './mdlUtils.js';
import {agent} from '@bedrock/https-agent';
import {generateKeyPair} from './certUtils.js';
import {mockData} from './mock.data.js';
import {oid4vp} from '@digitalbazaar/oid4-client';
import {randomUUID as uuid} from 'node:crypto';

const {baseUrl} = mockData;
const {getAuthorizationRequest} = oid4vp;

describe.skip('exchange w/ OID4VP mDL presentation', () => {
  let capabilityAgent;
  let deviceKeyPair;
  let mdlCertChain;
  let mdoc;
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

    // create workflow instance w/ oauth2-based authz
    const zcaps = {
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
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
          createAuthorizationRequest: 'authorizationRequest'
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });
    const authzReqUrl = `${exchangeId}/openid/client/authorization/request`;

    // get authorization request
    const {authorizationRequest} = await getAuthorizationRequest(
      {url: authzReqUrl, agent});

    should.exist(authorizationRequest);
    should.exist(authorizationRequest.presentation_definition);
    authorizationRequest.presentation_definition.id.should.be.a('string');
    authorizationRequest.presentation_definition.input_descriptors.should.be
      .an('array');
    authorizationRequest.response_mode.should.equal('direct_post');
    authorizationRequest.nonce.should.be.a('string');
    // FIXME: add assertions for `authorizationRequest.presentation_definition`

    // generate VPR from authorization request
    console.log('converted authorizationRequest',
      authorizationRequest);
    const {verifiablePresentationRequest} = await oid4vp.toVpr(
      {authorizationRequest});
    console.log('converted verifiablePresentationRequest',
      verifiablePresentationRequest);

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

    // create MDL enveloped presentation
    // FIXME: ensure `authorizationRequest.presentation_definition` is proper
    // for mDL presentation
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
    const verifiablePresentation = await mdlUtils.createPresentation({
      //presentationDefinition: authorizationRequest.presentation_definition,
      presentationDefinition,
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
        // FIXME: determine what this should be
        // format: {
        //   mso_mdoc: {
        //     alg: ['ES256']
        //   }
        // },
        path: '$'
      }]
    };
    const {result} = await oid4vp.sendAuthorizationResponse({
      vpToken, verifiablePresentation, authorizationRequest, agent,
      presentationSubmission
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

  it.skip('should fail w/invalid device signature', async () => {
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
          createAuthorizationRequest: 'authorizationRequest'
        }
      }
    };
    const {id: exchangeId} = await helpers.createExchange({
      url: `${workflowId}/exchanges`,
      capabilityAgent, capability: workflowRootZcap, exchange
    });
    const authzReqUrl = `${exchangeId}/openid/client/authorization/request`;

    // get authorization request
    const {authorizationRequest} = await getAuthorizationRequest(
      {url: authzReqUrl, agent});

    should.exist(authorizationRequest);
    should.exist(authorizationRequest.presentation_definition);
    authorizationRequest.presentation_definition.id.should.be.a('string');
    authorizationRequest.presentation_definition.input_descriptors.should.be
      .an('array');
    authorizationRequest.response_mode.should.equal('direct_post');
    authorizationRequest.nonce.should.be.a('string');
    // FIXME: add assertions for `authorizationRequest.presentation_definition`

    // generate VPR from authorization request
    const {verifiablePresentationRequest} = await oid4vp.toVpr(
      {authorizationRequest});

    // VPR should be the same as the one from the exchange, modulo changes
    // comply with OID4VP spec
    const expectedVpr = {
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
    };
    verifiablePresentationRequest.should.deep.equal(expectedVpr);

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
    const otherDeviceJwk = await generateKeyPair();

    // create MDL enveloped presentation
    const verifiablePresentation = await mdlUtils.createPresentation({
      presentationDefinition: authorizationRequest.presentation_definition,
      mdoc,
      sessionTranscript,
      devicePrivateJwk: otherDeviceJwk.privateJwk
    });

    // vpToken is base64url-encoded mDL device response
    const vpToken = verifiablePresentation.id.slice(
      verifiablePresentation.id.indexOf(',') + 1);

    // send authorization response
    // FIXME: auto-generate proper presentation submission
    const presentationSubmission = {
      id: 'ex:example',
      definition_id: 'ex:definition',
      descriptor_map: [{
        id: 'org.iso.18013.5.1.mDL',
        format: 'mso_mdoc',
        // FIXME: determine what this should be
        // format: {
        //   mso_mdoc: {
        //     alg: ['ES256']
        //   }
        // },
        path: '$'
      }]
    };
    const {result} = await oid4vp.sendAuthorizationResponse({
      vpToken, verifiablePresentation, authorizationRequest, agent,
      presentationSubmission
    });
    // should be only an optional `redirect_uri` in the response
    should.exist(result);
    //should.exist(result.redirect_uri);

    // exchange should NOT be complete and should have a `lastError`
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('pending');
        should.exist(exchange.lastError);
        exchange.lastError.name.should.equal('VerificationError');
        should.exist(exchange.lastError.errors);
        exchange.lastError.errors[0].name.should.equal('MDLError');
        exchange.lastError.errors[0].message.should.include(
          'Device signature must be valid');
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });
});
