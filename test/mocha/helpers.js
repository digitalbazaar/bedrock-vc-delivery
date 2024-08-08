/*!
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  generateKeyPair as _generateKeyPair,
  exportJWK,
  importJWK,
  SignJWT
} from 'jose';
import {AsymmetricKey, CapabilityAgent} from '@digitalbazaar/webkms-client';
import {createPresentation, signPresentation} from '@digitalbazaar/vc';
import {KeystoreAgent, KmsClient} from '@digitalbazaar/webkms-client';
import {agent} from '@bedrock/https-agent';
import {
  documentLoader as brDocumentLoader
} from '@bedrock/jsonld-document-loader';
import {decodeList} from '@digitalbazaar/vc-status-list';
import {didIo} from '@bedrock/did-io';
import {driver} from '@digitalbazaar/did-method-key';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {EdvClient} from '@digitalbazaar/edv-client';
import {generateId} from 'bnid';
import {getAppIdentity} from '@bedrock/app-identity';
import {httpClient} from '@digitalbazaar/http-client';
import {httpsAgent} from '@bedrock/https-agent';
import {v4 as uuid} from 'uuid';
import {ZcapClient} from '@digitalbazaar/ezcap';

import {mockData} from './mock.data.js';

const didKeyDriver = driver();
const edvBaseUrl = `${mockData.baseUrl}/edvs`;
const kmsBaseUrl = `${mockData.baseUrl}/kms`;

const FIVE_MINUTES = 1000 * 60 * 5;

// create document loader with contexts for VCs from `mock.data.js`
const contexts = new Map();
contexts.set(
  'https://www.w3.org/2018/credentials/examples/v1', mockData.examplesContext);

const documentLoader = async url => {
  const document = contexts.get(url);
  if(document !== undefined) {
    return {
      contextUrl: null,
      documentUrl: url,
      document,
      tag: 'static'
    };
  }
  return brDocumentLoader(url);
};

// Note: `userId` left here to model how systems would potentially integrate
// with VC-API exchange services
export async function createCredentialOffer({
  /*userId, */
  credentialDefinition, credentialId, variables,
  preAuthorized, userPinRequired = false,
  capabilityAgent, workflowId, workflowRootZcap,
  credentialFormat = 'ldp_vc',
  openId = true, openIdKeyPair
} = {}) {
  // first, create an exchange with variables based on the local user ID;
  // indicate that OID4VCI delivery is permitted
  const exchange = {
    // 15 minute expiry in seconds
    ttl: 60 * 15,
    // template variables
    variables: variables ? {
      issuanceDate: (new Date()).toISOString(),
      ...variables
    } : {
      credentialId: credentialId ?? `urn:uuid:${uuid()}`,
      issuanceDate: (new Date()).toISOString()
    }
  };
  let offer;
  if(openId) {
    // build OID4VCI oauth2 config
    const oauth2 = {};
    if(openIdKeyPair) {
      oauth2.keyPair = openIdKeyPair;
    } else {
      oauth2.generateKeyPair = {algorithm: 'ES256'};
    }
    if(!Array.isArray(credentialDefinition)) {
      credentialDefinition = [credentialDefinition];
    }
    const expectedCredentialRequests = credentialDefinition.map(
      credential_definition => ({
        format: credentialFormat, credential_definition
      }));
    exchange.openId = {expectedCredentialRequests, oauth2};

    // start building OID4VCI credential offer
    offer = {
      credential_issuer: '',
      // FIXME: use `credentials_supported` string IDs instead
      credentials: credentialDefinition.map(
        credential_definition => ({
          format: credentialFormat, credential_definition
        })),
      grants: {}
    };

    if(preAuthorized) {
      exchange.openId.preAuthorizedCode = await generateRandom();
      const grant = {'pre-authorized_code': exchange.openId.preAuthorizedCode};
      offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'] =
        grant;
      // `user_pin_required` default is `false` per the OID4VCI spec
      if(userPinRequired) {
        grant.user_pin_required = true;
      }
    } else {
      offer.grants.authorization_code = {
        // FIXME: implement
        issuer_state: 'eyJhbGciOiJSU0Et...FYUaBy'
      };
    }
  }
  const {id: exchangeId} = await createExchange({
    url: `${workflowId}/exchanges`,
    capabilityAgent, capability: workflowRootZcap, exchange
  });

  const result = {exchangeId};

  if(openId) {
    offer.credential_issuer = exchangeId;
    const searchParams = new URLSearchParams();
    searchParams.set('credential_offer', JSON.stringify(offer));
    result.openIdUrl = `openid-credential-offer://?${searchParams}`;
  }

  return result;
}

export async function createConfig({
  serviceType, url, capabilityAgent, ipAllowList, meterId, zcaps,
  configOptions = {}, oauth2 = false
} = {}) {
  if(!meterId) {
    // create a meter
    ({id: meterId} = await createMeter({capabilityAgent, serviceType}));
  }

  // create service object
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId,
    ...configOptions
  };
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }
  if(zcaps) {
    config.zcaps = zcaps;
  }
  if(oauth2) {
    const {baseUri} = bedrock.config.server;
    config.authorization = {
      oauth2: {
        issuerConfigUrl: `${baseUri}${mockData.oauth2IssuerConfigRoute}`
      }
    };
  }

  const zcapClient = createZcapClient({capabilityAgent});
  const response = await zcapClient.write({url, json: config});
  return response.data;
}

export async function createWorkflowConfig({
  capabilityAgent, ipAllowList, meterId, zcaps, credentialTemplates,
  steps, initialStep, oauth2 = false,
  configOptions = {credentialTemplates, steps, initialStep}
} = {}) {
  const url = `${mockData.baseUrl}/workflows`;
  return createConfig({
    serviceType: 'vc-workflow',
    url, capabilityAgent, ipAllowList, meterId, zcaps, configOptions, oauth2
  });
}

export async function createIssuerConfig({
  capabilityAgent, ipAllowList, meterId, zcaps, configOptions,
  statusListOptions, oauth2 = false
} = {}) {
  const url = `${mockData.baseUrl}/issuers`;
  // issuer-specific options
  configOptions = configOptions ?? {
    issueOptions: {
      suiteName: 'Ed25519Signature2020'
    },
    statusListOptions
  };
  return createConfig({
    serviceType: 'vc-issuer',
    url, capabilityAgent, ipAllowList, meterId, zcaps, configOptions, oauth2
  });
}

export async function createMeter({capabilityAgent, serviceType} = {}) {
  // create signer using the application's capability invocation key
  const {keys: {capabilityInvocationKey}} = getAppIdentity();

  const zcapClient = new ZcapClient({
    agent: httpsAgent,
    invocationSigner: capabilityInvocationKey.signer(),
    SuiteClass: Ed25519Signature2020
  });

  // create a meter
  const meterService = `${bedrock.config.server.baseUri}/meters`;
  let meter = {
    controller: capabilityAgent.id,
    product: {
      // mock ID for service type
      id: mockData.productIdMap.get(serviceType)
    }
  };
  ({data: {meter}} = await zcapClient.write({url: meterService, json: meter}));

  // return full meter ID
  const {id} = meter;
  return {id: `${meterService}/${id}`};
}

export async function createVerifierConfig({
  capabilityAgent, ipAllowList, meterId, zcaps, oauth2 = false
} = {}) {
  const url = `${mockData.baseUrl}/verifiers`;
  return createConfig({
    serviceType: 'vc-verifier',
    url, capabilityAgent, ipAllowList, meterId, zcaps, oauth2
  });
}

export async function generateKeyPair({algorithm = 'EdDSA'} = {}) {
  // generate keypair for AS
  const keyPair = await _generateKeyPair(algorithm, {extractable: true});
  const [privateKeyJwk, publicKeyJwk] = await Promise.all([
    exportJWK(keyPair.privateKey),
    exportJWK(keyPair.publicKey),
  ]);
  return {privateKeyJwk, publicKeyJwk};
}

export async function getConfig({id, capabilityAgent, accessToken}) {
  if(accessToken) {
    // do OAuth2
    const {data} = await httpClient.get(id, {
      agent: httpsAgent,
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    return data;
  }
  if(!capabilityAgent) {
    throw new Error('Either "capabilityAgent" or "accessToken" is required.');
  }
  // do zcap
  const zcapClient = createZcapClient({capabilityAgent});
  const {data} = await zcapClient.read({url: id});
  return data;
}

export async function getOAuth2AccessToken({
  configId, action, target, exp, iss, nbf, typ = 'at+jwt'
}) {
  const scope = `${action}:${target}`;
  const builder = new SignJWT({scope})
    .setProtectedHeader({alg: 'EdDSA', typ})
    .setIssuer(iss ?? mockData.oauth2Config.issuer)
    .setAudience(configId);
  if(exp !== undefined) {
    builder.setExpirationTime(exp);
  } else {
    // default to 5 minute expiration time
    builder.setExpirationTime('5m');
  }
  if(nbf !== undefined) {
    builder.setNotBefore(nbf);
  }
  const key = await importJWK({...mockData.ed25519KeyPair, alg: 'EdDSA'});
  return builder.sign(key);
}

export async function createDidAuthnVP({
  domain, challenge, verifiableCredential, did, signer
}) {
  if(!(did && signer)) {
    ({did, signer} = await createDidProofSigner());
  }
  const presentation = createPresentation({holder: did});
  if(verifiableCredential) {
    // use v2 context if VC is v2
    if(verifiableCredential['@context'].includes(
      'https://www.w3.org/ns/credentials/v2')) {
      presentation['@context'][0] = 'https://www.w3.org/ns/credentials/v2';
    }
    presentation.verifiableCredential = verifiableCredential;
  }
  // FIXME: add `envelope` (vc-jwt) option
  const verifiablePresentation = await signPresentation({
    suite: new Ed25519Signature2020({signer}),
    presentation, domain, challenge,
    documentLoader
  });
  return {verifiablePresentation, did};
}

export async function createDidProofSigner() {
  const {didDocument, methodFor} = await didKeyDriver.generate();
  const authenticationKeyPair = methodFor({purpose: 'authentication'});
  const keyPair = await Ed25519Multikey.from(authenticationKeyPair);
  return {did: didDocument.id, signer: keyPair.signer()};
}

export async function createExchange({
  url, capabilityAgent, capability, exchange
}) {
  const zcapClient = createZcapClient({capabilityAgent});
  const response = await zcapClient.write({url, json: exchange, capability});
  const exchangeId = response.headers.get('location');
  return {id: exchangeId};
}

export async function getExchange({id, capabilityAgent, accessToken} = {}) {
  if(accessToken) {
    // do OAuth2
    const {data} = await httpClient.get(id, {
      agent: httpsAgent,
      headers: {
        authorization: `Bearer ${accessToken}`
      }
    });
    return data;
  }
  if(!capabilityAgent) {
    throw new Error('Either "capabilityAgent" or "accessToken" is required.');
  }
  // do zcap
  const zcapClient = createZcapClient({capabilityAgent});
  // assume root zcap for associated workflow
  const workflowId = id.slice(0, id.lastIndexOf('/exchanges/'));
  const capability = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
  const {data} = await zcapClient.read({url: id, capability});
  return data;
}

export async function createEdv({
  capabilityAgent, keystoreAgent, keyAgreementKey, hmac, meterId
}) {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await createMeter({
      capabilityAgent, serviceType: 'edv'
    }));
  }

  if(!(keyAgreementKey && hmac) && keystoreAgent) {
    // create KAK and HMAC keys for edv config
    ([keyAgreementKey, hmac] = await Promise.all([
      keystoreAgent.generateKey({type: 'keyAgreement'}),
      keystoreAgent.generateKey({type: 'hmac'})
    ]));
  }

  // create edv
  const newEdvConfig = {
    sequence: 0,
    controller: capabilityAgent.id,
    keyAgreementKey: {id: keyAgreementKey.id, type: keyAgreementKey.type},
    hmac: {id: hmac.id, type: hmac.type},
    meterId
  };

  const edvConfig = await EdvClient.createEdv({
    config: newEdvConfig,
    httpsAgent,
    invocationSigner: capabilityAgent.getSigner(),
    url: edvBaseUrl
  });

  const edvClient = new EdvClient({
    id: edvConfig.id,
    keyResolver,
    keyAgreementKey,
    hmac,
    httpsAgent
  });

  return {edvClient, edvConfig, hmac, keyAgreementKey};
}

export async function createKeystore({
  capabilityAgent, ipAllowList, meterId,
  kmsModule = 'ssm-v1'
}) {
  if(!meterId) {
    // create a meter for the keystore
    ({id: meterId} = await createMeter(
      {capabilityAgent, serviceType: 'webkms'}));
  }

  // create keystore
  const config = {
    sequence: 0,
    controller: capabilityAgent.id,
    meterId,
    kmsModule
  };
  if(ipAllowList) {
    config.ipAllowList = ipAllowList;
  }

  return KmsClient.createKeystore({
    url: `${kmsBaseUrl}/keystores`,
    config,
    invocationSigner: capabilityAgent.getSigner(),
    httpsAgent
  });
}

export async function createKeystoreAgent({capabilityAgent, ipAllowList}) {
  let err;
  let keystore;
  try {
    keystore = await createKeystore({capabilityAgent, ipAllowList});
  } catch(e) {
    err = e;
  }
  assertNoError(err);

  // create kmsClient only required because we need to use httpsAgent
  // that accepts self-signed certs used in test suite
  const kmsClient = new KmsClient({httpsAgent});
  const keystoreAgent = new KeystoreAgent({
    capabilityAgent,
    keystoreId: keystore.id,
    kmsClient
  });

  return keystoreAgent;
}

export function createZcapClient({
  capabilityAgent, delegationSigner, invocationSigner
}) {
  const signer = capabilityAgent && capabilityAgent.getSigner();
  return new ZcapClient({
    agent: httpsAgent,
    invocationSigner: invocationSigner || signer,
    delegationSigner: delegationSigner || signer,
    SuiteClass: Ed25519Signature2020
  });
}

export async function delegate({
  capability, controller, invocationTarget, expires, allowedActions,
  delegator
}) {
  const zcapClient = createZcapClient({capabilityAgent: delegator});
  expires = expires || (capability && capability.expires) ||
    new Date(Date.now() + FIVE_MINUTES).toISOString().slice(0, -5) + 'Z';
  return zcapClient.delegate({
    capability, controller, expires, invocationTarget, allowedActions
  });
}

export function generateRandom() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}

export async function getCredentialStatus({verifiableCredential}) {
  // get SLC for the VC
  const {credentialStatus} = verifiableCredential;
  if(Array.isArray(credentialStatus)) {
    throw new Error('Multiple credential statuses not supported.');
  }
  let slcUrl;
  let statusListIndexProperty;
  if(credentialStatus.type === 'RevocationList2020Status') {
    slcUrl = credentialStatus.revocationListCredential;
    statusListIndexProperty = 'revocationListIndex';
  } else {
    slcUrl = credentialStatus.statusListCredential;
    statusListIndexProperty = 'statusListIndex';
  }
  if(!slcUrl) {
    throw new Error('Status list credential missing from credential status.');
  }
  const {data: slc} = await httpClient.get(slcUrl, {agent: httpsAgent});

  const {encodedList} = slc.credentialSubject;
  const list = await decodeList({encodedList});
  const statusListIndex = parseInt(
    credentialStatus[statusListIndexProperty], 10);
  const status = list.getStatus(statusListIndex);
  return {status, statusListCredential: slcUrl};
}

export async function provisionDependencies({issuerOptions} = {}) {
  const secret = '53ad64ce-8e1d-11ec-bb12-10bf48838a41';
  const handle = 'test';
  const capabilityAgent = await CapabilityAgent.fromSecret({secret, handle});

  // create keystore for capability agent
  const keystoreAgent = await createKeystoreAgent({capabilityAgent});

  // FIXME: a verifier instance isn't necessary for single-step exchanges or
  // exchanges that do not do any DID Authn, but this method provisions a
  // verifier anyway; this could be parameterized later to better test when
  // this is needed and when it isn't
  const [
    {
      issuerConfig,
      workflowIssueZcap,
      workflowCredentialStatusZcap
    },
    {
      verifierConfig,
      workflowCreateChallengeZcap,
      workflowVerifyPresentationZcap
    }
  ] = await Promise.all([
    provisionIssuer({capabilityAgent, keystoreAgent, issuerOptions}),
    provisionVerifier({capabilityAgent, keystoreAgent})
  ]);

  return {
    issuerConfig, workflowIssueZcap, workflowCredentialStatusZcap,
    verifierConfig, workflowCreateChallengeZcap,
    workflowVerifyPresentationZcap,
    capabilityAgent
  };
}

export async function provisionIssuer({
  capabilityAgent, keystoreAgent, issuerOptions = {}
}) {
  // get service agent to delegate to
  const issuerServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-issuer')}`;
  const {data: issuerServiceAgent} = await httpClient.get(
    issuerServiceAgentUrl, {agent});

  const zcaps = {};
  const {keystoreId} = keystoreAgent;
  const keystoreRootZcap = createRootZcap({url: keystoreId});

  // generate asymmetric key(s) for issuance
  let assertionMethodKey;
  const {issueOptions} = issuerOptions;
  if(!issueOptions) {
    // generate key for signing VCs (make it a did:key DID for simplicity)
    assertionMethodKey = await keystoreAgent.generateKey({
      type: 'asymmetric',
      publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
    });
    // delegate assertion method key to issuer service agent
    zcaps.assertionMethod = await delegate({
      capability: keystoreRootZcap,
      controller: issuerServiceAgent.id,
      invocationTarget: assertionMethodKey.kmsId,
      delegator: capabilityAgent
    });
  } else {
    const {did, cryptosuites = [], envelope} = issueOptions;
    const suites = cryptosuites.slice();
    if(envelope) {
      suites.push(envelope);
    }
    if(suites.length > 0) {
      // auto-generate DID using `did:key` if no `did` given
      const publicAliasTemplate = did ?
        `${did}#{publicKeyMultibase}` :
        'did:key:{publicKeyMultibase}#{publicKeyMultibase}';

      // generate an assertion method key for each cryptosuite and / or envelope
      for(const suite of suites) {
        const {algorithm} = suite;
        if(suite.assertionMethodKey) {
          // key already set
          continue;
        }
        suite.assertionMethodKey = await generateAsymmetricKey({
          keystoreAgent, algorithm, publicAliasTemplate
        });
        // use any assertion method key
        assertionMethodKey = suite.assertionMethodKey;
      }

      // delegate zcaps for each cryptosuite
      await delegateAssertionMethodZcaps({
        envelope, cryptosuites, serviceAgent: issuerServiceAgent,
        capabilityAgent, zcaps
      });
    }
  }

  // create EDV for storage (creating hmac and kak in the process)
  const {
    edvConfig,
    hmac,
    keyAgreementKey
  } = await createEdv({capabilityAgent, keystoreAgent});

  // delegate edv, hmac, and key agreement key zcaps to service agent
  const {id: edvId} = edvConfig;
  zcaps.edv = await delegate({
    controller: issuerServiceAgent.id,
    delegator: capabilityAgent,
    invocationTarget: edvId
  });
  zcaps.hmac = await delegate({
    capability: keystoreRootZcap,
    controller: issuerServiceAgent.id,
    invocationTarget: hmac.id,
    delegator: capabilityAgent
  });
  zcaps.keyAgreementKey = await delegate({
    capability: keystoreRootZcap,
    controller: issuerServiceAgent.id,
    invocationTarget: keyAgreementKey.kmsId,
    delegator: capabilityAgent
  });

  // generate config options based on issue options
  let configOptions;
  if(issueOptions) {
    const keyDescription = await assertionMethodKey.getKeyDescription();
    const keyController = keyDescription.id.startsWith('did:key:') ?
      keyDescription.id.slice(0, keyDescription.id.indexOf('#')) :
      keyDescription.controller;
    const {issuer, cryptosuites, envelope} = issueOptions;
    configOptions = {
      issueOptions: {
        issuer: issuer ?? keyController
      }
    };
    if(cryptosuites) {
      configOptions.issueOptions.cryptosuites = cryptosuites.map(suite => {
        const {name, options, zcapReferenceIds} = suite;
        const cryptosuite = {name, zcapReferenceIds};
        if(options) {
          cryptosuite.options = options;
        }
        return cryptosuite;
      });
    }
    if(envelope) {
      configOptions.issueOptions.envelope = {
        format: envelope.format,
        options: envelope.options,
        zcapReferenceIds: envelope.zcapReferenceIds
      };
    }
  }

  // create issuer instance w/ oauth2-based authz
  const issuerConfig = await createIssuerConfig(
    {capabilityAgent, zcaps, oauth2: true, configOptions});
  const {id: issuerId} = issuerConfig;
  const issuerRootZcap = createRootZcap({url: issuerId});

  // insert examples context
  const examplesContextId = 'https://www.w3.org/2018/credentials/examples/v1';
  const {examplesContext} = mockData;
  const client = createZcapClient({capabilityAgent});
  const url = `${issuerId}/contexts`;
  await client.write({
    url, json: {id: examplesContextId, context: examplesContext},
    capability: issuerRootZcap
  });

  // insert prc context
  const prcContextId = 'https://w3id.org/citizenship/v1';
  const {prcCredentialContext} = mockData;
  await client.write({
    url, json: {id: prcContextId, context: prcCredentialContext},
    capability: issuerRootZcap
  });

  // delegate issuer root zcap to workflow service
  const workflowServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-workflow')}`;
  const {data: workflowServiceAgent} = await httpClient.get(
    workflowServiceAgentUrl, {agent});

  // zcap to issue a credential
  const workflowIssueZcap = await delegate({
    capability: issuerRootZcap,
    controller: workflowServiceAgent.id,
    invocationTarget: `${issuerId}/credentials/issue`,
    delegator: capabilityAgent
  });

  // zcap to set the status of a credential
  const workflowCredentialStatusZcap = await delegate({
    capability: issuerRootZcap,
    controller: workflowServiceAgent.id,
    invocationTarget: `${issuerId}/credentials/status`,
    delegator: capabilityAgent
  });

  return {issuerConfig, workflowIssueZcap, workflowCredentialStatusZcap};
}

export async function provisionVerifier({capabilityAgent, keystoreAgent}) {
  // create EDV for storage (creating hmac and kak in the process)
  const {
    edvConfig,
    hmac,
    keyAgreementKey
  } = await createEdv({capabilityAgent, keystoreAgent});

  // get service agent to delegate to
  const veriferServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-verifier')}`;
  const {data: veriferServiceAgent} = await httpClient.get(
    veriferServiceAgentUrl, {agent});

  // delegate edv, hmac, and key agreement key zcaps to service agent
  const {id: edvId} = edvConfig;
  const zcaps = {};
  zcaps.edv = await delegate({
    controller: veriferServiceAgent.id,
    delegator: capabilityAgent,
    invocationTarget: edvId
  });
  const {keystoreId} = keystoreAgent;
  zcaps.hmac = await delegate({
    capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
    controller: veriferServiceAgent.id,
    invocationTarget: hmac.id,
    delegator: capabilityAgent
  });
  zcaps.keyAgreementKey = await delegate({
    capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
    controller: veriferServiceAgent.id,
    invocationTarget: keyAgreementKey.kmsId,
    delegator: capabilityAgent
  });

  // create verifer instance w/ oauth2-based authz
  const verifierConfig = await createVerifierConfig(
    {capabilityAgent, zcaps, oauth2: true});
  const {id: verifierId} = verifierConfig;
  const verifierRootZcap = `urn:zcap:root:${encodeURIComponent(verifierId)}`;

  // delegate verifier root zcap to workflow service
  const workflowServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-workflow')}`;
  const {data: workflowServiceAgent} = await httpClient.get(
    workflowServiceAgentUrl, {agent});

  // zcap to create a challenge
  const workflowCreateChallengeZcap = await delegate({
    capability: verifierRootZcap,
    controller: workflowServiceAgent.id,
    invocationTarget: `${verifierId}/challenges`,
    delegator: capabilityAgent
  });

  // zcap to verify a presentation
  const workflowVerifyPresentationZcap = await delegate({
    capability: verifierRootZcap,
    controller: workflowServiceAgent.id,
    invocationTarget: `${verifierId}/presentations/verify`,
    delegator: capabilityAgent
  });

  return {
    verifierConfig,
    workflowCreateChallengeZcap,
    workflowVerifyPresentationZcap
  };
}

export async function revokeDelegatedCapability({
  serviceObjectId, capabilityToRevoke, invocationSigner
}) {
  const url = `${serviceObjectId}/zcaps/revocations/` +
    encodeURIComponent(capabilityToRevoke.id);
  const zcapClient = createZcapClient({invocationSigner});
  return zcapClient.write({url, json: capabilityToRevoke});
}

async function keyResolver({id}) {
  // support DID-based keys only
  if(id.startsWith('did:')) {
    return didIo.get({url: id});
  }
  // support HTTP-based keys; currently a requirement for WebKMS
  const {data} = await httpClient.get(id, {agent: httpsAgent});
  return data;
}

function createRootZcap({url}) {
  return `urn:zcap:root:${encodeURIComponent(url)}`;
}

async function delegateAssertionMethodZcaps({
  envelope, cryptosuites = [], serviceAgent,
  capabilityAgent, zcaps = {}
} = {}) {
  // can treat any envelope input as a cryptosuite here
  const suites = (cryptosuites || []).slice();
  if(envelope) {
    suites.push(envelope);
  }

  // delegate any assertion method keys not yet delegated
  for(const suite of suites) {
    // only delegate zcap once as the service agent is always the same
    let referenceId = suite.zcapReferenceIds?.assertionMethod;
    if(!referenceId) {
      const {assertionMethodKey} = suite;
      const zcap = await delegate({
        capability: createRootZcap({
          url: parseKeystoreId(assertionMethodKey.kmsId)
        }),
        controller: serviceAgent.id,
        invocationTarget: assertionMethodKey.kmsId,
        delegator: capabilityAgent
      });
      referenceId = zcap.id;
      suite.zcaps = suite.zcaps ?? {};
      suite.zcaps[referenceId] = zcap;
      suite.zcapReferenceIds = suite.zcapReferenceIds ?? {};
      suite.zcapReferenceIds.assertionMethod = referenceId;
    }
    zcaps[referenceId] = suite.zcaps[referenceId];
  }
  return zcaps;
}

async function generateAsymmetricKey({
  keystoreAgent, algorithm, publicAliasTemplate
}) {
  if(['P-256', 'P-384', 'Bls12381G2'].includes(algorithm)) {
    return _generateMultikey({
      keystoreAgent,
      type: `urn:webkms:multikey:${algorithm}`,
      publicAliasTemplate
    });
  }
  return keystoreAgent.generateKey({
    type: 'asymmetric',
    publicAliasTemplate
  });
}

function parseKeystoreId(keyId) {
  // key ID format: <baseUrl>/<keystores-path>/<keystore-id>/keys/<key-id>
  const idx = keyId.lastIndexOf('/keys/');
  if(idx === -1) {
    throw new Error(`Invalid key ID "${keyId}".`);
  }
  return keyId.slice(0, idx);
}

async function _generateMultikey({
  keystoreAgent, type, publicAliasTemplate
}) {
  const {capabilityAgent, kmsClient} = keystoreAgent;
  const invocationSigner = capabilityAgent.getSigner();
  const {keyId, keyDescription} = await kmsClient.generateKey({
    type,
    suiteContextUrl: 'https://w3id.org/security/multikey/v1',
    invocationSigner,
    publicAliasTemplate
  });
  const {id} = keyDescription;
  ({type} = keyDescription);
  return new AsymmetricKey({
    id, kmsId: keyId, type, invocationSigner, kmsClient, keyDescription
  });
}
