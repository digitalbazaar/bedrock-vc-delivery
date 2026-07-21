/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as helpers from './helpers.js';
import {getCredentialOffer, OID4Client} from '@digitalbazaar/oid4-client';
import {Holder, IssuerSigned} from '@owf/mdoc';
import {agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {mdocContext} from './mdlUtils.js';
import {mockData} from './mock.data.js';
import {randomUUID as uuid} from 'node:crypto';

import {generateCertificateChain} from './certUtils.js';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

describe('exchange w/OID4VCI that issues mdoc mDL', () => {
  let did;
  let capabilityAgent;
  let certificateEntities;
  let issuerCertificateChain;
  let workflowId;
  let workflowRootZcap;
  beforeEach(async () => {
    // generate a `did:web` DID for the issuer
    const {host} = bedrock.config.server;
    const localId = uuid();
    did = `did:web:${encodeURIComponent(host)}:did-web:${localId}`;

    // HACK: provision dependencies that will create the key to issue mDL and
    // update `envelope` input with its details; this is needed to create the
    // certificate chain -- the issuer instance will be discarded; another
    // issuer instance will be created below that will be used in the test
    const envelope = {
      mediaType: 'application/mdl',
      algorithm: 'P-256'
    };
    await helpers.provisionDependencies({
      issuerOptions: {
        issueOptions: {did, issuer: did, envelope}
      }
    });

    // create `did:web` DID document for issuer
    const didDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://w3id.org/security/multikey/v1'
      ],
      id: did,
      verificationMethod: [],
      assertionMethod: []
    };
    let issuerKeyPair;
    let issuerPublicJwk;
    for(const {assertionMethodKey} of [envelope]) {
      const description = await assertionMethodKey.getKeyDescription();
      delete description['@context'];
      description.controller = did;
      didDocument.verificationMethod.push(description);
      didDocument.assertionMethod.push(description.id);
      issuerKeyPair = await EcdsaMultikey.from(description);
      issuerPublicJwk = await EcdsaMultikey.toJwk({keyPair: issuerKeyPair});
    }
    // add DID doc to map with DID docs to be served
    mockData.didWebDocuments.set(localId, didDocument);

    // create a certificate chain that ends in the MDL issuer (leaf)
    certificateEntities = await generateCertificateChain({
      leafConfig: {
        // FIXME: leaf must be marked as a CA to pass verification; investigate
        // to see if this is correct or not and adjust accordingly
        cA: true,
        keyPairInfo: {
          keyPair: issuerKeyPair,
          jwk: issuerPublicJwk
        }
      }
    });
    issuerCertificateChain = [certificateEntities.leaf.pemCertificate];

    // create issue options
    const issueOptions = {
      did,
      issuer: did,
      envelope: {
        mediaType: envelope.mediaType,
        options: {issuerCertificateChain},
        zcapReferenceIds: envelope.zcapReferenceIds,
        zcaps: envelope.zcaps
      }
    };

    // now create dependencies for issuance
    const deps = await helpers.provisionDependencies({
      issuerOptions: {issueOptions}
    });
    const {
      workflowIssueZcap,
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    } = deps;
    ({capabilityAgent} = deps);

    // create workflow instance
    const zcaps = {
      issue: workflowIssueZcap,
      createChallenge: workflowCreateChallengeZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
    const credentialTemplates = [{
      type: 'jsonata',
      template: structuredClone(mockData.vdlTemplate)
    }];
    const steps = {
      issue: {
        stepTemplate: {
          type: 'jsonata',
          template: `
          {
            /* start only needed for VC-API delivery */
            "createChallenge": true,
            "verifiablePresentationRequest": {
              "query": {
                "type": "DIDAuthentication",
                "acceptedMethods": [{"method": "key"}]
              },
              "domain": domain
            },
            /* end only needed for VC-API delivery */
            "issueRequests": [{
              "issuerInstanceId": issuerInstanceId,
              "credentialTemplateIndex": 0,
              "oid4vci": issueRequestOid4vci
            }],
            "divpDidProofRequest": divpDidProofRequest,
            "jwtDidProofRequest": jwtDidProofRequest
          }`
        }
      }
    };
    const configOptions = {
      credentialTemplates,
      steps,
      initialStep: 'issue',
      issuerInstances: [{
        id: 'mdoc-mdl-issuer-instance',
        oid4vci: {
          supportedCredentialConfigurations: {
            'org.iso.18013.5.1.mDL_di_vp_did_auth': {
              format: 'mso_mdoc',
              doctype: 'org.iso.18013.5.1.mDL',
              cryptographic_binding_methods_supported: ['cose_key'],
              credential_signing_alg_values_supported: [-7, -9],
              proof_types_supported: {
                di_vp: {
                  proof_signing_alg_values_supported: ['ecdsa-rdfc-2019']
                }
              }
            },
            'org.iso.18013.5.1.mDL_jwt_did_auth': {
              format: 'mso_mdoc',
              doctype: 'org.iso.18013.5.1.mDL',
              cryptographic_binding_methods_supported: ['cose_key'],
              credential_signing_alg_values_supported: [-7, -9],
              proof_types_supported: {
                jwt: {
                  proof_signing_alg_values_supported: ['ES256']
                }
              }
            }
          }
        },
        supportedMediaTypes: ['application/mdl'],
        zcapReferenceIds: {
          issue: 'issue'
        }
      }]
    };
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent, zcaps, configOptions, oauth2: true,
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  });

  it('should pass w/ di_vp DID Auth', async () => {
    // pre-authorized flow, issuer-initiated
    const {offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      variables: {
        domain: mockData.baseUrl,
        issueRequestOid4vci: {
          credentialConfigurationId: 'org.iso.18013.5.1.mDL_di_vp_did_auth'
        },
        divpDidProofRequest: {
          acceptedMethods: [{method: 'key'}]
        }
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      useCredentialOfferUri: true
    });

    // get offer from server
    const offer = await getCredentialOffer({url: offerUrl, agent});
    offer.credential_configuration_ids.should.deep.equal(
      ['org.iso.18013.5.1.mDL_di_vp_did_auth']);

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({
      offer, agent, supportedFormats: ['mso_mdoc']
    });

    const {
      did, signer: didProofSigner
    } = await helpers.createDidProofSigner({algorithm: 'P-256'});

    // wallet / client receives credential(s)
    const result = await client.requestCredentials({
      agent, getDidOptions: () => ({did, didProofSigner}),
      format: 'mso_mdoc'
    });
    should.exist(result);
    result.should.include.keys('credential_responses');
    const allCredentials = [];
    for(const r of result.credential_responses) {
      r.should.include.keys(['credentials']);
      for(const element of r.credentials) {
        element.should.include.keys(['credential']);
        allCredentials.push(element.credential);
      }
    }
    allCredentials.length.should.equal(1);

    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: offer.credential_issuer, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
      } catch(error) {
        err = error;
      }
      assertNoError(err);
    }

    const [b64Url] = allCredentials;
    b64Url.should.be.a('string');

    // assert mDL contents
    const encodedIssuerSigned = Buffer.from(b64Url, 'base64url');
    // decode issuerSigned directly — no CBOR container wrapping needed
    const issuerSigned = IssuerSigned.decode(encodedIssuerSigned);
    const rawFields = issuerSigned.getPrettyClaims(MDL_NAMESPACE);

    // @owf/mdoc decodes nested CBOR maps as JS Map instances; convert to
    // plain objects for comparison
    const fields = _deepMapToObject(rawFields);

    // issuer signed document should have matching fields from
    // credential subject's driver's license
    const {mockVdl} = mockData;
    const expectedFields = {...mockVdl.credentialSubject.driversLicense};
    delete expectedFields.type;

    should.exist(fields);
    issuerSigned.issuerAuth.mobileSecurityObject.docType.should.equal(
      MDOC_TYPE_MDL);
    fields.should.deep.equal(expectedFields);

    // verify issuer signature on mDL
    const trustedCertificates = [
      certificateEntities.intermediate.pemCertificate,
      certificateEntities.root.pemCertificate
    ].map(pem => new Uint8Array(Buffer.from(
      pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64')));

    await Holder.verifyIssuerSigned(
      {issuerSigned, trustedCertificates},
      mdocContext);
  });

  it('should pass w/ jwt DID Auth', async () => {
    // pre-authorized flow, issuer-initiated
    const {offerUrl} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      variables: {
        domain: mockData.baseUrl,
        issueRequestOid4vci: {
          credentialConfigurationId: 'org.iso.18013.5.1.mDL_jwt_did_auth'
        },
        jwtDidProofRequest: {
          acceptedMethods: [{method: 'key'}]
        }
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      useCredentialOfferUri: true
    });

    // get offer from server
    const offer = await getCredentialOffer({url: offerUrl, agent});
    offer.credential_configuration_ids.should.deep.equal(
      ['org.iso.18013.5.1.mDL_jwt_did_auth']);

    // wallet / client gets access token
    const client = await OID4Client.fromCredentialOffer({
      offer, agent, supportedFormats: ['mso_mdoc']
    });

    const {
      did, signer: didProofSigner
    } = await helpers.createDidProofSigner({algorithm: 'P-256'});

    // wallet / client receives credential(s)
    const result = await client.requestCredentials({
      agent, getDidOptions: () => ({did, didProofSigner}),
      format: 'mso_mdoc'
    });
    should.exist(result);
    result.should.include.keys('credential_responses');
    const allCredentials = [];
    for(const r of result.credential_responses) {
      r.should.include.keys(['credentials']);
      for(const element of r.credentials) {
        element.should.include.keys(['credential']);
        allCredentials.push(element.credential);
      }
    }
    allCredentials.length.should.equal(1);

    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: offer.credential_issuer, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
      } catch(error) {
        err = error;
      }
      assertNoError(err);
    }

    const [b64Url] = allCredentials;
    b64Url.should.be.a('string');

    // assert mDL contents
    const encodedIssuerSigned = Buffer.from(b64Url, 'base64url');

    // decode issuerSigned directly — no CBOR container wrapping needed
    const issuerSigned = IssuerSigned.decode(encodedIssuerSigned);
    const rawFields = issuerSigned.getPrettyClaims(MDL_NAMESPACE);

    // @owf/mdoc decodes nested CBOR maps as JS Map instances; convert to
    // plain objects for comparison
    const fields = _deepMapToObject(rawFields);

    // issuer signed document should have matching fields from
    // credential subject's driver's license
    const {mockVdl} = mockData;
    const expectedFields = {...mockVdl.credentialSubject.driversLicense};
    delete expectedFields.type;

    should.exist(fields);
    issuerSigned.issuerAuth.mobileSecurityObject.docType.should.equal(
      MDOC_TYPE_MDL);
    fields.should.deep.equal(expectedFields);

    // verify issuer signature on mDL
    const trustedCertificates = [
      certificateEntities.intermediate.pemCertificate,
      certificateEntities.root.pemCertificate
    ].map(pem => new Uint8Array(Buffer.from(
      pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64')));

    await Holder.verifyIssuerSigned(
      {issuerSigned, trustedCertificates},
      mdocContext);
  });

  it('should pass w/ VC-API delivery', async () => {
    // pre-authorized flow, issuer-initiated
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      variables: {
        issuerInstanceId: 'mdoc-mdl-issuer-instance',
        domain: mockData.baseUrl
      },
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap,
      useCredentialOfferUri: true
    });

    // post to get VPR
    let vpr;
    {
      const response = await httpClient.post(exchangeId, {agent, json: {}});
      vpr = response.data.verifiablePresentationRequest;
    }

    const {
      did, signer
    } = await helpers.createDidProofSigner({algorithm: 'P-256'});

    // generate VP
    const {challenge, domain} = vpr;
    const {verifiablePresentation} = await helpers.createDidAuthnVP({
      challenge,
      domain,
      did, signer
    });

    // post VP to get VP in response
    let vcs;
    {
      const response = await httpClient.post(
        exchangeId, {agent, json: {verifiablePresentation}});
      should.exist(response.data?.verifiablePresentation?.verifiableCredential);
      vcs = response.data.verifiablePresentation.verifiableCredential;
      vcs.length.should.equal(1);
    }

    // exchange state should be complete
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
      } catch(error) {
        err = error;
      }
      assertNoError(err);
    }

    const [verifiableCredential] = vcs;
    verifiableCredential.type.should.equal('EnvelopedVerifiableCredential');

    // assert mDL contents
    const b64 = verifiableCredential.id
      .slice('data:application/mdl;base64,'.length);
    const encodedIssuerSigned = Buffer.from(b64, 'base64');
    // decode issuerSigned directly — no CBOR container wrapping needed
    const issuerSigned = IssuerSigned.decode(encodedIssuerSigned);
    const rawFields = issuerSigned.getPrettyClaims(MDL_NAMESPACE);

    // @owf/mdoc decodes nested CBOR maps as JS Map instances; convert to
    // plain objects for comparison
    const fields = _deepMapToObject(rawFields);

    // issuer signed document should have matching fields from
    // credential subject's driver's license
    const {mockVdl} = mockData;
    const expectedFields = {...mockVdl.credentialSubject.driversLicense};
    delete expectedFields.type;

    should.exist(fields);
    issuerSigned.issuerAuth.mobileSecurityObject.docType.should.equal(
      MDOC_TYPE_MDL);
    fields.should.deep.equal(expectedFields);

    // verify issuer signature on mDL
    const trustedCertificates = [
      certificateEntities.intermediate.pemCertificate,
      certificateEntities.root.pemCertificate
    ].map(pem => new Uint8Array(Buffer.from(
      pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''), 'base64')));

    await Holder.verifyIssuerSigned(
      {issuerSigned, trustedCertificates},
      mdocContext);
  });
});

function _deepMapToObject(value) {
  // handle native Map
  if(value instanceof Map) {
    const obj = {};
    for(const [k, v] of value) {
      obj[k] = _deepMapToObject(v);
    }
    return obj;
  }
  // handle @owf/mdoc's TypedMap, which wraps a native Map in a .map property
  if(value?.map instanceof Map) {
    const obj = {};
    for(const [k, v] of value.map) {
      obj[k] = _deepMapToObject(v);
    }
    return obj;
  }
  if(Array.isArray(value)) {
    return value.map(_deepMapToObject);
  }
  // recurse into plain objects so nested Maps are converted
  if(value !== null && typeof value === 'object') {
    const obj = {};
    for(const [k, v] of Object.entries(value)) {
      obj[k] = _deepMapToObject(v);
    }
    return obj;
  }
  return value;
}
