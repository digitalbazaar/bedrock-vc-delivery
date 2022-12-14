/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {createPresentation, signPresentation} from '@digitalbazaar/vc';
import {exportJWK, generateKeyPair, importJWK, SignJWT} from 'jose';
import {KeystoreAgent, KmsClient} from '@digitalbazaar/webkms-client';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
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

// Note: `userId` left here to model how systems would potentially integrate
// with VC-API exchange services
export async function createCredentialOffer({
  /*userId, */credentialType, credentialId,
  preAuthorized, userPinRequired = false,
  capabilityAgent, exchangerId, exchangerRootZcap, oidc4vci = true
} = {}) {
  // first, create an exchange with variables based on the local user ID;
  // indicate that OIDC4VCI delivery is permitted
  const exchange = {
    // 15 minute expiry in seconds
    ttl: 60 * 15,
    // template variables
    variables: {
      credentialId: credentialId ?? `urn:uuid:${uuid()}`,
      issuanceDate: (new Date()).toISOString()
    }
  };
  if(oidc4vci) {
    // generate keypair for AS
    const keyPair = await generateKeyPair('EdDSA', {extractable: true});
    const [privateKeyJwk, publicKeyJwk] = await Promise.all([
      exportJWK(keyPair.privateKey),
      exportJWK(keyPair.publicKey),
    ]);
    exchange.oidc4vci = {
      oauth2: {
        keyPair: {privateKeyJwk, publicKeyJwk}
      }
    };
    if(preAuthorized) {
      exchange.oidc4vci.preAuthorizedCode = await _generateRandom();
    }
  }
  const result = await createExchange({
    url: `${exchangerId}/exchanges`,
    capabilityAgent, capability: exchangerRootZcap, exchange
  });
  const {id: exchangeId} = result;

  // FIXME: only build this if OIDC4VCI is permitted for the exchange
  const searchParams = new URLSearchParams();
  searchParams.set('issuer', exchangeId);
  searchParams.set('credential_type', credentialType);
  if(preAuthorized) {
    searchParams.set(
      'pre-authorized_code', exchange.oidc4vci.preAuthorizedCode);
  }
  if(userPinRequired) {
    searchParams.set('user_pin_required', true);
  }
  const oidc4vciUrl = `openid-initiate-issuance://?${searchParams}`;

  return {oidc4vciUrl, exchangeId};
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

export async function createExchangerConfig({
  capabilityAgent, ipAllowList, meterId, zcaps, credentialTemplates,
  steps, initialStep, oauth2 = false
} = {}) {
  const url = `${mockData.baseUrl}/exchangers`;
  const configOptions = {credentialTemplates, steps, initialStep};
  return createConfig({
    serviceType: 'vc-exchanger',
    url, capabilityAgent, ipAllowList, meterId, zcaps, configOptions, oauth2
  });
}

export async function createIssuerConfig({
  capabilityAgent, ipAllowList, meterId, zcaps,
  statusListOptions, oauth2 = false
} = {}) {
  const url = `${mockData.baseUrl}/issuers`;
  // issuer-specific options
  const configOptions = {
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

export async function createDidAuthnVP({domain, challenge}) {
  const {did, signer} = await createDidProofSigner();
  const presentation = createPresentation({holder: did});
  const verifiablePresentation = await signPresentation({
    suite: new Ed25519Signature2020({signer}),
    presentation, domain, challenge
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

export async function provisionDependencies() {
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
      exchangerIssueZcap,
      exchangerCredentialStatusZcap
    },
    {
      verifierConfig,
      exchangerCreateChallengeZcap,
      exchangerVerifyPresentationZcap
    }
  ] = await Promise.all([
    provisionIssuer({capabilityAgent, keystoreAgent}),
    provisionVerifier({capabilityAgent, keystoreAgent})
  ]);

  return {
    issuerConfig, exchangerIssueZcap, exchangerCredentialStatusZcap,
    verifierConfig, exchangerCreateChallengeZcap,
    exchangerVerifyPresentationZcap,
    capabilityAgent
  };
}

export async function provisionIssuer({capabilityAgent, keystoreAgent}) {
  // generate key for signing VCs (make it a did:key DID for simplicity)
  const assertionMethodKey = await keystoreAgent.generateKey({
    type: 'asymmetric',
    publicAliasTemplate: 'did:key:{publicKeyMultibase}#{publicKeyMultibase}'
  });

  // create EDV for storage (creating hmac and kak in the process)
  const {
    edvConfig,
    hmac,
    keyAgreementKey
  } = await createEdv({capabilityAgent, keystoreAgent});

  // get service agent to delegate to
  const issuerServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-issuer')}`;
  const {data: issuerServiceAgent} = await httpClient.get(
    issuerServiceAgentUrl, {agent});

  // delegate edv, hmac, and key agreement key zcaps to service agent
  const {id: edvId} = edvConfig;
  const zcaps = {};
  zcaps.edv = await delegate({
    controller: issuerServiceAgent.id,
    delegator: capabilityAgent,
    invocationTarget: edvId
  });
  const {keystoreId} = keystoreAgent;
  zcaps.hmac = await delegate({
    capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
    controller: issuerServiceAgent.id,
    invocationTarget: hmac.id,
    delegator: capabilityAgent
  });
  zcaps.keyAgreementKey = await delegate({
    capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
    controller: issuerServiceAgent.id,
    invocationTarget: keyAgreementKey.kmsId,
    delegator: capabilityAgent
  });
  zcaps['assertionMethod:ed25519'] = await delegate({
    capability: `urn:zcap:root:${encodeURIComponent(keystoreId)}`,
    controller: issuerServiceAgent.id,
    invocationTarget: assertionMethodKey.kmsId,
    delegator: capabilityAgent
  });

  // create issuer instance w/ oauth2-based authz
  const issuerConfig = await createIssuerConfig(
    {capabilityAgent, zcaps, oauth2: true});
  const {id: issuerId} = issuerConfig;
  const issuerRootZcap = `urn:zcap:root:${encodeURIComponent(issuerId)}`;

  // insert mock context
  const contextId = 'https://test.example/v1';
  const context = {'@context': {term: 'https://test.example#term'}};
  const client = createZcapClient({capabilityAgent});
  const url = `${issuerId}/contexts`;
  await client.write({
    url, json: {id: contextId, context},
    capability: issuerRootZcap
  });

  // delegate issuer root zcap to exchanger service
  const exchangerServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-exchanger')}`;
  const {data: exchangerServiceAgent} = await httpClient.get(
    exchangerServiceAgentUrl, {agent});

  // zcap to issue a credential
  const exchangerIssueZcap = await delegate({
    capability: issuerRootZcap,
    controller: exchangerServiceAgent.id,
    invocationTarget: `${issuerId}/credentials/issue`,
    delegator: capabilityAgent
  });

  // zcap to set the status of a credential
  const exchangerCredentialStatusZcap = await delegate({
    capability: issuerRootZcap,
    controller: exchangerServiceAgent.id,
    invocationTarget: `${issuerId}/credentials/status`,
    delegator: capabilityAgent
  });

  return {issuerConfig, exchangerIssueZcap, exchangerCredentialStatusZcap};
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

  // delegate verifier root zcap to exchanger service
  const exchangerServiceAgentUrl =
    `${mockData.baseUrl}/service-agents/${encodeURIComponent('vc-exchanger')}`;
  const {data: exchangerServiceAgent} = await httpClient.get(
    exchangerServiceAgentUrl, {agent});

  // zcap to create a challenge
  const exchangerCreateChallengeZcap = await delegate({
    capability: verifierRootZcap,
    controller: exchangerServiceAgent.id,
    invocationTarget: `${verifierId}/challenges`,
    delegator: capabilityAgent
  });

  // zcap to verify a presentation
  const exchangerVerifyPresentationZcap = await delegate({
    capability: verifierRootZcap,
    controller: exchangerServiceAgent.id,
    invocationTarget: `${verifierId}/presentations/verify`,
    delegator: capabilityAgent
  });

  return {
    verifierConfig,
    exchangerCreateChallengeZcap,
    exchangerVerifyPresentationZcap
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

function _generateRandom() {
  // 128-bit random number, base58 multibase + multihash encoded
  return generateId({
    bitLength: 128,
    encoding: 'base58',
    multibase: true,
    multihash: true
  });
}
