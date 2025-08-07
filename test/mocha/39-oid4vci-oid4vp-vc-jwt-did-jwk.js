/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {
  getCredentialOffer, OID4Client, oid4vp, parseCredentialOfferUrl
} from '@digitalbazaar/oid4-client';
import {agent} from '@bedrock/https-agent';
import {createPresentation} from '@digitalbazaar/vc';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';
import {
  unenvelopeCredential
} from '@bedrock/vc-delivery/lib/helpers.js';
import {randomUUID as uuid} from 'node:crypto';

const {
  baseUrl, nameCredentialTemplate, nameCredentialDefinition,
  namePresentationSchema
} = mockData;
const credentialFormat = 'jwt_vc_json-ld';

const VC_CONTEXT_1 = 'https://www.w3.org/2018/credentials/v1';

describe('exchange w/OID4VCI + OID4VP VC with VC-JWT w/did:jwk', () => {
  let capabilityAgent;

  // provision a VC to use in the workflow below
  let verifiableCredential;
  let did;
  let signer;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies({
      issuerOptions: {
        issueOptions: {
          // cryptosuites: [{
          //   name: 'Ed25519Signature2020'
          // }]
          envelope: {
            format: 'VC-JWT',
            algorithm: 'Ed25519',
            // works with or without options, but `EdDSA` will be chosen
            // over `Ed25519` if `alg` not given an an Ed25519 key is used
            /*options: {
              alg: 'Ed25519'
            }*/
          }
        }
      }
    });
    const {
      workflowIssueZcap,
      workflowCredentialStatusZcap,
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    const zcaps = {
      issue: workflowIssueZcap,
      credentialStatus: workflowCredentialStatusZcap,
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: nameCredentialTemplate
    }];
    // require semantically-named workflow steps
    const steps = {
      // DID Authn step
      didAuthn: {
        createChallenge: true,
        verifiablePresentationRequest: {
          query: {
            type: 'DIDAuthentication',
            acceptedMethods: [{method: 'key'}]
          },
          domain: baseUrl
        }
      }
    };
    // set initial step
    const initialStep = 'didAuthn';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, credentialTemplates, steps, initialStep,
      oauth2: true
    });
    const workflowId = workflowConfig.id;
    const workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;

    // use workflow to provision verifiable credential
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: nameCredentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });

    // generate VP
    ({did, signer} = await helpers.createDidProofSigner({didMethod: 'jwk'}));
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      domain: baseUrl,
      challenge: exchangeId.slice(exchangeId.lastIndexOf('/') + 1),
      did, signer
    });

    // post VP to get VP w/VC in response
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    const {verifiablePresentation: vp} = response.data;
    verifiableCredential = vp.verifiableCredential[0];
  });

  // provision workflow that will require the provisioned VC above
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies({
      issuerOptions: {
        issueOptions: {
          // cryptosuites: [{
          //   name: 'Ed25519Signature2020'
          // }]
          envelope: {
            format: 'VC-JWT',
            algorithm: 'Ed25519',
            // works with or without options, but `EdDSA` will be chosen
            // over `Ed25519` if `alg` not given an an Ed25519 key is used
            /*options: {
              alg: 'Ed25519'
            }*/
          }
        }
      }
    });
    const {
      workflowIssueZcap,
      workflowCredentialStatusZcap,
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    const zcaps = {
      issue: workflowIssueZcap,
      credentialStatus: workflowCredentialStatusZcap,
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: nameCredentialTemplate
    }];
    // require semantically-named workflow steps
    const steps = {
      // DID Authn step
      didAuthn: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            "presentationSchema": presentationSchema,
            "createChallenge": true,
            "verifiablePresentationRequest": verifiablePresentationRequest,
            "openId": {
              "createAuthorizationRequest": "authorizationRequest",
              "client_id_scheme": "redirect_uri",
              "client_id": globals.workflow.id &
                "/exchanges/" &
                globals.exchange.id &
                "/openid/client/authorization/response"
            }
          }`
        }
      }
    };
    // set initial step
    const initialStep = 'didAuthn';
    const configOptions = {
      credentialTemplates, steps, initialStep,
      issuerInstances: [{
        supportedFormats: ['jwt_vc_json-ld'],
        zcapReferenceIds: {
          issue: 'issue'
        }
      }]
    };
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, configOptions, oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  // FIXME: add invalid issuer test that will fail against `presentationSchema`

  it('should pass w/ pre-authorized code flow', async () => {
    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    const vpr = {
      query: [{
        type: 'DIDAuthentication',
        acceptedMethods: [{method: 'key'}],
        acceptedCryptosuites: [{cryptosuite: 'Ed25519Signature2020'}]
      }, {
        type: 'QueryByExample',
        credentialQuery: [{
          reason: 'We require a name verifiable credential to pass this test',
          example: {
            '@context': 'https://www.w3.org/2018/credentials/v1',
            type: 'VerifiableCredential',
            credentialSubject: {
              'ex:name': ''
            }
          }
        }]
      }],
      domain: baseUrl
    };
    const jsonSchema = structuredClone(namePresentationSchema);
    // FIXME: create a function to inject required `issuer` value
    jsonSchema.properties.verifiableCredential.oneOf[0]
      .properties.issuer = {const: verifiableCredential.issuer};
    jsonSchema.properties.verifiableCredential.oneOf[1].items
      .properties.issuer = {const: verifiableCredential.issuer};
    const {
      exchangeId,
      openIdUrl: issuanceUrl
    } = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: nameCredentialDefinition,
      credentialFormat,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      variables: {
        credentialId,
        verifiablePresentationRequest: vpr,
        presentationSchema: {
          type: 'JsonSchema',
          jsonSchema
        },
        openId: {
          createAuthorizationRequest: 'authorizationRequest'
        }
      }
    });
    const chapiRequest = {OID4VCI: issuanceUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const offer = parseCredentialOfferUrl({url: parsedChapiRequest.OID4VCI});

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client attempts to receive credential, should receive a
    // `presentation_required` error with an authorization request
    let error;
    try {
      await client.requestCredential({
        credentialDefinition: nameCredentialDefinition,
        did,
        didProofSigner: signer,
        agent,
        format: credentialFormat
      });
    } catch(e) {
      error = e;
    }
    should.exist(error);
    should.exist(error.cause);
    error.cause.name.should.equal('NotAllowedError');
    should.exist(error.cause.cause);
    error.cause.cause.data.error.should.equal('presentation_required');
    should.exist(error.cause.cause.data.authorization_request);

    // wallet / client responds to `authorization_request` by performing
    // OID4VP:
    let envelopedPresentation;
    {
      // generate VPR from authorization request
      const {
        cause: {
          cause: {data: {authorization_request: authorizationRequest}}
        }
      } = error;
      const {verifiablePresentationRequest} = await oid4vp.toVpr(
        {authorizationRequest});

      // VPR should be the same as the one from the exchange, modulo changes
      // comply with OID4VP spec
      const expectedVpr = {
        query: [{
          type: 'DIDAuthentication',
          // no OID4VP support for accepted DID methods at this time
          acceptedCryptosuites: [
            {cryptosuite: 'ecdsa-rdfc-2019'},
            {cryptosuite: 'eddsa-rdfc-2022'},
            {cryptosuite: 'Ed25519Signature2020'}
          ]
        }, {
          type: 'QueryByExample',
          credentialQuery: [{
            reason: 'We require a name verifiable credential to pass this test',
            example: {
              '@context': 'https://www.w3.org/2018/credentials/v1',
              type: 'VerifiableCredential',
              credentialSubject: {
                'ex:name': ''
              }
            }
          }]
        }],
        // OID4VP requires this to be the authz response URL
        domain: authorizationRequest.response_uri,
        // challenge should be set to authz nonce
        challenge: authorizationRequest.nonce
      };
      verifiablePresentationRequest.should.deep.equal(expectedVpr);

      // generate enveloped VP
      const {domain, challenge} = verifiablePresentationRequest;
      const presentation = createPresentation({holder: did});
      // force VC-JWT 1.1 mode with `verifiableCredential` as a string
      presentation['@context'] = [VC_CONTEXT_1];
      const credentialJwt = verifiableCredential.id.slice(
        'data:application/jwt,'.length);
      presentation.verifiableCredential = [credentialJwt];
      const envelopeResult = await helpers.envelopePresentation({
        verifiablePresentation: presentation,
        challenge,
        domain,
        signer
      });
      ({envelopedPresentation} = envelopeResult);
      const {jwt} = envelopeResult;

      // send authorization response
      // FIXME: auto-generate proper presentation submission
      const presentationSubmission = {
        id: 'ex:example',
        definition_id: 'ex:definition',
        descriptor_map: []
      };
      const {
        result/*, presentationSubmission*/
      } = await oid4vp.sendAuthorizationResponse({
        verifiablePresentation: presentation, authorizationRequest,
        vpToken: JSON.stringify(jwt), agent,
        presentationSubmission
      });
      should.exist(result);

      // exchange should be `active` and contain the VP and open ID results
      {
        let err;
        try {
          const {exchange} = await helpers.getExchange(
            {id: exchangeId, capabilityAgent});
          should.exist(exchange?.state);
          exchange.state.should.equal('active');
          should.exist(exchange?.variables?.results?.didAuthn);
          should.exist(
            exchange?.variables?.results?.didAuthn?.verifiablePresentation);
          exchange?.variables?.results?.didAuthn.did.should.equal(did);
          exchange.variables.results.didAuthn.envelopedPresentation
            .should.deep.equal(envelopedPresentation);
          exchange.variables.results.didAuthn.verifiablePresentation.holder
            .should.equal(did);
          should.exist(exchange.variables.results.didAuthn.openId);
          exchange.variables.results.didAuthn.openId.authorizationRequest
            .should.deep.equal(authorizationRequest);
          exchange.variables.results.didAuthn.openId.presentationSubmission
            .should.deep.equal(presentationSubmission);
        } catch(error) {
          err = error;
        }
        should.not.exist(err, err?.message);
      }
    }

    // wallet / client attempts to receive credential now that OID4VP is done
    let result;
    error = undefined;
    try {
      result = await client.requestCredential({
        credentialDefinition: nameCredentialDefinition,
        did,
        didProofSigner: signer,
        agent,
        format: credentialFormat
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal(credentialFormat);
    result.credential.should.be.a('string');
    const {credential} = await unenvelopeCredential({
      envelopedCredential: result.credential,
      format: credentialFormat
    });
    // ensure credential subject ID matches generated DID
    should.exist(credential?.credentialSubject?.id);
    credential.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(credential.id);
    credential.id.should.equal(credentialId);

    // exchange should be complete and contain the VP and original VC
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.didAuthn);
        should.exist(
          exchange?.variables?.results?.didAuthn?.verifiablePresentation);
        exchange?.variables?.results?.didAuthn.did.should.equal(did);
        exchange.variables.results.didAuthn.verifiablePresentation.holder
          .should.deep.equal(did);
        exchange.variables.results.didAuthn.envelopedPresentation
          .should.deep.equal(envelopedPresentation);
      } catch(error) {
        err = error;
      }
      should.not.exist(err, err?.message);
    }
  });

  it('should pass w/ "credential_offer_uri"', async () => {
    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    const vpr = {
      query: [{
        type: 'DIDAuthentication',
        acceptedMethods: [{method: 'key'}],
        acceptedCryptosuites: [{cryptosuite: 'Ed25519Signature2020'}]
      }, {
        type: 'QueryByExample',
        credentialQuery: [{
          reason: 'We require a name verifiable credential to pass this test',
          example: {
            '@context': 'https://www.w3.org/2018/credentials/v1',
            type: 'VerifiableCredential',
            credentialSubject: {
              'ex:name': ''
            }
          }
        }]
      }],
      domain: baseUrl
    };
    const jsonSchema = structuredClone(namePresentationSchema);
    // FIXME: create a function to inject required `issuer` value
    jsonSchema.properties.verifiableCredential.oneOf[0]
      .properties.issuer = {const: verifiableCredential.issuer};
    jsonSchema.properties.verifiableCredential.oneOf[1].items
      .properties.issuer = {const: verifiableCredential.issuer};
    const {
      exchangeId,
      openIdUrl: issuanceUrl
    } = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: nameCredentialDefinition,
      credentialFormat,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      variables: {
        credentialId,
        verifiablePresentationRequest: vpr,
        presentationSchema: {
          type: 'JsonSchema',
          jsonSchema
        },
        openId: {
          createAuthorizationRequest: 'authorizationRequest'
        }
      },
      useCredentialOfferUri: true
    });
    const chapiRequest = {OID4VCI: issuanceUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const offer = await getCredentialOffer({
      url: parsedChapiRequest.OID4VCI, agent
    });

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client attempts to receive credential, should receive a
    // `presentation_required` error with an authorization request
    let error;
    try {
      await client.requestCredential({
        did,
        didProofSigner: signer,
        agent,
        format: credentialFormat
      });
    } catch(e) {
      error = e;
    }
    should.exist(error);
    should.exist(error.cause);
    error.cause.name.should.equal('NotAllowedError');
    should.exist(error.cause.cause);
    error.cause.cause.data.error.should.equal('presentation_required');
    should.exist(error.cause.cause.data.authorization_request);

    // wallet / client responds to `authorization_request` by performing
    // OID4VP:
    let envelopedPresentation;
    {
      // generate VPR from authorization request
      const {
        cause: {
          cause: {data: {authorization_request: authorizationRequest}}
        }
      } = error;
      const {verifiablePresentationRequest} = await oid4vp.toVpr(
        {authorizationRequest});

      // VPR should be the same as the one from the exchange, modulo changes
      // comply with OID4VP spec
      const expectedVpr = {
        query: [{
          type: 'DIDAuthentication',
          // no OID4VP support for accepted DID methods at this time
          acceptedCryptosuites: [
            {cryptosuite: 'ecdsa-rdfc-2019'},
            {cryptosuite: 'eddsa-rdfc-2022'},
            {cryptosuite: 'Ed25519Signature2020'}
          ]
        }, {
          type: 'QueryByExample',
          credentialQuery: [{
            reason: 'We require a name verifiable credential to pass this test',
            example: {
              '@context': 'https://www.w3.org/2018/credentials/v1',
              type: 'VerifiableCredential',
              credentialSubject: {
                'ex:name': ''
              }
            }
          }]
        }],
        // OID4VP requires this to be the authz response URL
        domain: authorizationRequest.response_uri,
        // challenge should be set to authz nonce
        challenge: authorizationRequest.nonce
      };
      verifiablePresentationRequest.should.deep.equal(expectedVpr);

      // generate enveloped VP
      const {domain, challenge} = verifiablePresentationRequest;
      const presentation = createPresentation({holder: did});
      // force VC-JWT 1.1 mode with `verifiableCredential` as a string
      presentation['@context'] = [VC_CONTEXT_1];
      const credentialJwt = verifiableCredential.id.slice(
        'data:application/jwt,'.length);
      presentation.verifiableCredential = [credentialJwt];
      const envelopeResult = await helpers.envelopePresentation({
        verifiablePresentation: presentation,
        challenge,
        domain,
        signer
      });
      ({envelopedPresentation} = envelopeResult);
      const {jwt} = envelopeResult;

      // send authorization response
      // FIXME: auto-generate proper presentation submission
      const presentationSubmission = {
        id: 'ex:example',
        definition_id: 'ex:definition',
        descriptor_map: []
      };
      const {
        result/*, presentationSubmission*/
      } = await oid4vp.sendAuthorizationResponse({
        verifiablePresentation: presentation, authorizationRequest,
        vpToken: JSON.stringify(jwt), agent,
        presentationSubmission
      });
      should.exist(result);

      // exchange should be `active` and contain the VP and open ID results
      {
        let err;
        try {
          const {exchange} = await helpers.getExchange(
            {id: exchangeId, capabilityAgent});
          should.exist(exchange?.state);
          exchange.state.should.equal('active');
          should.exist(exchange?.variables?.results?.didAuthn);
          should.exist(
            exchange?.variables?.results?.didAuthn?.verifiablePresentation);
          exchange?.variables?.results?.didAuthn.did.should.equal(did);
          exchange.variables.results.didAuthn.envelopedPresentation
            .should.deep.equal(envelopedPresentation);
          exchange.variables.results.didAuthn.verifiablePresentation.holder
            .should.equal(did);
          should.exist(exchange.variables.results.didAuthn.openId);
          exchange.variables.results.didAuthn.openId.authorizationRequest
            .should.deep.equal(authorizationRequest);
          exchange.variables.results.didAuthn.openId.presentationSubmission
            .should.deep.equal(presentationSubmission);
        } catch(error) {
          err = error;
        }
        should.not.exist(err, err?.message);
      }
    }

    // wallet / client attempts to receive credential now that OID4VP is done
    let result;
    error = undefined;
    try {
      result = await client.requestCredential({
        did,
        didProofSigner: signer,
        agent,
        format: credentialFormat
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal(credentialFormat);
    result.credential.should.be.a('string');
    const {credential} = await unenvelopeCredential({
      envelopedCredential: result.credential,
      format: credentialFormat
    });
    // ensure credential subject ID matches generated DID
    should.exist(credential?.credentialSubject?.id);
    credential.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(credential.id);
    credential.id.should.equal(credentialId);

    // exchange should be complete and contain the VP and original VC
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.didAuthn);
        should.exist(
          exchange?.variables?.results?.didAuthn?.verifiablePresentation);
        exchange?.variables?.results?.didAuthn.did.should.equal(did);
        exchange.variables.results.didAuthn.verifiablePresentation.holder
          .should.deep.equal(did);
        exchange.variables.results.didAuthn.envelopedPresentation
          .should.deep.equal(envelopedPresentation);
      } catch(error) {
        err = error;
      }
      should.not.exist(err, err?.message);
    }
  });

  it('should pass w/ "credential_offer_uri" + "acceptedEnvelopes', async () => {
    // pre-authorized flow, issuer-initiated
    const credentialId = `urn:uuid:${uuid()}`;
    const vpr = {
      query: [{
        type: 'DIDAuthentication',
        acceptedMethods: [{method: 'key'}],
        acceptedCryptosuites: [{cryptosuite: 'Ed25519Signature2020'}]
      }, {
        type: 'QueryByExample',
        credentialQuery: [{
          reason: 'We require a name verifiable credential to pass this test',
          example: {
            '@context': 'https://www.w3.org/2018/credentials/v1',
            type: 'VerifiableCredential',
            credentialSubject: {
              'ex:name': ''
            }
          },
          acceptedEnvelopes: ['application/jwt']
        }]
      }],
      domain: baseUrl
    };
    const jsonSchema = structuredClone(namePresentationSchema);
    // FIXME: create a function to inject required `issuer` value
    jsonSchema.properties.verifiableCredential.oneOf[0]
      .properties.issuer = {const: verifiableCredential.issuer};
    jsonSchema.properties.verifiableCredential.oneOf[1].items
      .properties.issuer = {const: verifiableCredential.issuer};
    const {
      exchangeId,
      openIdUrl: issuanceUrl
    } = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: nameCredentialDefinition,
      credentialFormat,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      variables: {
        credentialId,
        verifiablePresentationRequest: vpr,
        presentationSchema: {
          type: 'JsonSchema',
          jsonSchema
        },
        openId: {
          createAuthorizationRequest: 'authorizationRequest'
        }
      },
      useCredentialOfferUri: true
    });
    const chapiRequest = {OID4VCI: issuanceUrl};
    // CHAPI could potentially be used to deliver the URL to a native app
    // that registered a "claimed URL" of `https://myapp.examples/ch`
    // like so:
    const claimedUrlFromChapi = 'https://myapp.example/ch?request=' +
      encodeURIComponent(JSON.stringify(chapiRequest));
    const parsedClaimedUrl = new URL(claimedUrlFromChapi);
    const parsedChapiRequest = JSON.parse(
      parsedClaimedUrl.searchParams.get('request'));
    const offer = await getCredentialOffer({
      url: parsedChapiRequest.OID4VCI, agent
    });

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({offer, agent});

    // wallet / client attempts to receive credential, should receive a
    // `presentation_required` error with an authorization request
    let error;
    try {
      await client.requestCredential({
        did,
        didProofSigner: signer,
        agent,
        format: credentialFormat
      });
    } catch(e) {
      error = e;
    }
    should.exist(error);
    should.exist(error.cause);
    error.cause.name.should.equal('NotAllowedError');
    should.exist(error.cause.cause);
    error.cause.cause.data.error.should.equal('presentation_required');
    should.exist(error.cause.cause.data.authorization_request);

    // wallet / client responds to `authorization_request` by performing
    // OID4VP:
    let envelopedPresentation;
    {
      // generate VPR from authorization request
      const {
        cause: {
          cause: {data: {authorization_request: authorizationRequest}}
        }
      } = error;
      const {verifiablePresentationRequest} = await oid4vp.toVpr(
        {authorizationRequest});

      // VPR should be the same as the one from the exchange, modulo changes
      // comply with OID4VP spec
      const expectedVpr = {
        query: [{
          type: 'DIDAuthentication',
          // no OID4VP support for accepted DID methods at this time
          acceptedCryptosuites: [
            {cryptosuite: 'ecdsa-rdfc-2019'},
            {cryptosuite: 'eddsa-rdfc-2022'},
            {cryptosuite: 'Ed25519Signature2020'}
          ]
        }, {
          type: 'QueryByExample',
          credentialQuery: [{
            reason: 'We require a name verifiable credential to pass this test',
            example: {
              '@context': 'https://www.w3.org/2018/credentials/v1',
              type: 'VerifiableCredential',
              credentialSubject: {
                'ex:name': ''
              }
            },
            // FIXME: format conversion not yet supported
            //acceptedEnvelopes: ['application/jwt']
          }]
        }],
        // OID4VP requires this to be the authz response URL
        domain: authorizationRequest.response_uri,
        // challenge should be set to authz nonce
        challenge: authorizationRequest.nonce
      };
      verifiablePresentationRequest.should.deep.equal(expectedVpr);

      // generate enveloped VP
      const {domain, challenge} = verifiablePresentationRequest;
      const presentation = createPresentation({holder: did});
      // force VC-JWT 1.1 mode with `verifiableCredential` as a string
      presentation['@context'] = [VC_CONTEXT_1];
      const credentialJwt = verifiableCredential.id.slice(
        'data:application/jwt,'.length);
      presentation.verifiableCredential = [credentialJwt];
      const envelopeResult = await helpers.envelopePresentation({
        verifiablePresentation: presentation,
        challenge,
        domain,
        signer
      });
      ({envelopedPresentation} = envelopeResult);
      const {jwt} = envelopeResult;

      // send authorization response
      // FIXME: auto-generate proper presentation submission
      const presentationSubmission = {
        id: 'ex:example',
        definition_id: 'ex:definition',
        descriptor_map: []
      };
      const {
        result/*, presentationSubmission*/
      } = await oid4vp.sendAuthorizationResponse({
        verifiablePresentation: presentation, authorizationRequest,
        vpToken: JSON.stringify(jwt), agent,
        presentationSubmission
      });
      should.exist(result);

      // exchange should be `active` and contain the VP and open ID results
      {
        let err;
        try {
          const {exchange} = await helpers.getExchange(
            {id: exchangeId, capabilityAgent});
          should.exist(exchange?.state);
          exchange.state.should.equal('active');
          should.exist(exchange?.variables?.results?.didAuthn);
          should.exist(
            exchange?.variables?.results?.didAuthn?.verifiablePresentation);
          exchange?.variables?.results?.didAuthn.did.should.equal(did);
          exchange.variables.results.didAuthn.envelopedPresentation
            .should.deep.equal(envelopedPresentation);
          exchange.variables.results.didAuthn.verifiablePresentation.holder
            .should.equal(did);
          should.exist(exchange.variables.results.didAuthn.openId);
          exchange.variables.results.didAuthn.openId.authorizationRequest
            .should.deep.equal(authorizationRequest);
          exchange.variables.results.didAuthn.openId.presentationSubmission
            .should.deep.equal(presentationSubmission);
        } catch(error) {
          err = error;
        }
        should.not.exist(err, err?.message);
      }
    }

    // wallet / client attempts to receive credential now that OID4VP is done
    let result;
    error = undefined;
    try {
      result = await client.requestCredential({
        did,
        didProofSigner: signer,
        agent,
        format: credentialFormat
      });
    } catch(e) {
      error = e;
    }
    should.not.exist(error);
    should.exist(result);
    result.should.include.keys(['format', 'credential']);
    result.format.should.equal(credentialFormat);
    result.credential.should.be.a('string');
    const {credential} = await unenvelopeCredential({
      envelopedCredential: result.credential,
      format: credentialFormat
    });
    // ensure credential subject ID matches generated DID
    should.exist(credential?.credentialSubject?.id);
    credential.credentialSubject.id.should.equal(did);
    // ensure VC ID matches
    should.exist(credential.id);
    credential.id.should.equal(credentialId);

    // exchange should be complete and contain the VP and original VC
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        should.exist(exchange?.variables?.results?.didAuthn);
        should.exist(
          exchange?.variables?.results?.didAuthn?.verifiablePresentation);
        exchange?.variables?.results?.didAuthn.did.should.equal(did);
        exchange.variables.results.didAuthn.verifiablePresentation.holder
          .should.deep.equal(did);
        exchange.variables.results.didAuthn.envelopedPresentation
          .should.deep.equal(envelopedPresentation);
      } catch(error) {
        err = error;
      }
      should.not.exist(err, err?.message);
    }
  });
});
