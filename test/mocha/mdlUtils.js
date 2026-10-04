/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc.
 */
import {
  CoseKey, DeviceKey,
  IsoMdocDcApi,
  //IssuerSigned,
  Issuer as MDocIssuer,
  SignatureAlgorithm
} from '@owf/mdoc';
import {DeviceResponse, Document, MDoc, /*parse,*/ Verifier} from '@auth0/mdl';
import {exportJWK, importX509} from 'jose';
import {webcrypto, X509Certificate} from 'node:crypto';
import {decode as cborDecode} from 'cborg';
import {oid4vp} from '@digitalbazaar/oid4-client';

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

const {encodeSessionTranscript} = oid4vp.mdoc;

// mdocContext implements the crypto/cose/x509 interfaces required by @owf/mdoc
export const mdocContext = {
  crypto: {
    async digest({digestAlgorithm, bytes}) {
      const digest = await webcrypto.subtle.digest(
        digestAlgorithm, bytes);
      return new Uint8Array(digest);
    },
    random(length) {
      return webcrypto.getRandomValues(new Uint8Array(length));
    }
  },
  cose: {
    sign1: {
      async sign({key, toBeSigned}) {
        const cryptoKey = await webcrypto.subtle.importKey(
          'jwk', _cleanJwk(key.jwk),
          {name: 'ECDSA', namedCurve: 'P-256'},
          false, ['sign']);
        const sig = await webcrypto.subtle.sign(
          {name: 'ECDSA', hash: 'SHA-256'}, cryptoKey, toBeSigned);
        return new Uint8Array(sig);
      },
      async verify({signature, key, toBeVerified}) {
        const cryptoKey = await webcrypto.subtle.importKey(
          'jwk', _cleanJwk(key.jwk),
          {name: 'ECDSA', namedCurve: 'P-256'},
          false, ['verify']);
        return webcrypto.subtle.verify(
          {name: 'ECDSA', hash: 'SHA-256'}, cryptoKey,
          signature, toBeVerified);
      }
    }
  },
  x509: {
    getSubjectNameField({certificate, field}) {
      const cert = new X509Certificate(certificate);
      return _parseDN(cert.subject)[field] ?? [];
    },
    getIssuerNameField({certificate, field}) {
      const cert = new X509Certificate(certificate);
      return _parseDN(cert.issuer)[field] ?? [];
    },
    async getPublicKey({certificate, alg, algorithm}) {
      const cert = new X509Certificate(certificate);
      if(!alg && algorithm) {
        if(algorithm === -7) {
          alg = 'ES256';
        } else if(algorithm === -35) {
          alg = 'ES384';
        }
      }
      const key = await importX509(cert.toString(), alg, {extractable: true});
      return CoseKey.fromJwk(await exportJWK(key));
    },
    async verifyCertificateChain({trustedCertificates, x5chain, now}) {
      if(x5chain.length === 0) {
        throw new Error('Certificate chain is empty');
      }
      const chain = x5chain.map(c => new X509Certificate(c));
      const trusted = trustedCertificates.map(c => new X509Certificate(c));

      // do minimal checking: verify each cert in the chain is issued by the
      // next; do NOT copy this code to verify a cert chain in a real app, it
      // is likely not sufficient
      for(let i = 0; i < chain.length - 1; ++i) {
        const cert = chain[i];
        const issuer = chain[i + 1];
        if(!cert.checkIssued(issuer)) {
          throw new Error(
            `Certificate at index ${i} was not issued by ` +
            `certificate at index ${i + 1}`);
        }
        if(!cert.verify(issuer.publicKey)) {
          throw new Error(
            `Certificate at index ${i} failed signature verification`);
        }
        _checkValidity(cert, now);
      }

      // the last cert in the chain must be trusted (or self-signed by trusted)
      let trustedCertificate;
      const lastCert = chain[chain.length - 1];
      const isTrusted = trusted.some(t => {
        try {
          if(lastCert.verify(t.publicKey) && lastCert.checkIssued(t)) {
            trustedCertificate = t;
            return true;
          }
          return false;
        } catch(e) {
          return false;
        }
      });
      if(!isTrusted) {
        throw new Error(
          'No trusted certificate was found while validating the X.509 chain');
      }
      _checkValidity(lastCert, now);

      return {
        // return verified chain + trusted certificate it descends from
        chain: [
          ...x5chain.slice(), new Uint8Array(trustedCertificate.rawData)
        ]
      };
    },
    async getCertificateData({certificate}) {
      const cert = new X509Certificate(certificate);
      // fingerprint256 is "XX:XX:..." — strip colons for a hex thumbprint
      const thumbprint = cert.fingerprint256.replace(/:/g, '').toLowerCase();
      return {
        issuerName: cert.issuer,
        subjectName: cert.subject,
        pem: cert.toString(),
        serialNumber: cert.serialNumber,
        thumbprint,
        notBefore: new Date(cert.validFrom),
        notAfter: new Date(cert.validTo)
      };
    }
  }
};

export function coseKeyToJwk({coseKey} = {}) {
  // convert from `@owf/mdoc` structure if necessary
  if(!(coseKey instanceof Map) && typeof coseKey.encode === 'function') {
    const cbor = coseKey.encode();
    coseKey = cborDecode(cbor, {useMaps: true});
  }

  const kty = coseKey.get(1) === 2 ? 'EC' : undefined;
  const crvId = coseKey.get(-1);
  let crv;
  if(crvId === 1) {
    crv = 'P-256';
  } else if(crv === 2) {
    crv = 'P-384';
  }
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);

  if(!(kty === 'EC' && (crv === 'P-256' || crv === 'P-384'))) {
    throw new Error(
      'Unknown supported COSE key for mdoc decryption; ' +
      'only EC (2), P-256 (1) or P-384 (2) are accepted.');
  }

  // https://datatracker.ietf.org/doc/html/rfc9053
  return {
    kty,
    crv,
    x: Buffer.from(x).toString('base64url'),
    y: Buffer.from(y).toString('base64url')
  };
}

export async function createPresentation({
  dcApiRequest, origin,
  presentationDefinition,
  mdoc, /* issuerSigned, */
  handover, devicePrivateJwk
} = {}) {
  if(dcApiRequest?.protocol === 'org-iso-mdoc') {
    const parsedRequest = await IsoMdocDcApi.parseRequest({
      request: dcApiRequest.data, origin
    }, mdocContext);

    // convert doc request into DCQL
    const credentials = parsedRequest.docRequests.map(docRequest => {
      const {namespaces} = docRequest;
      const claims = [];
      for(const [namespace, fields] of namespaces) {
        for(const field of fields.keys()) {
          claims.push({
            path: [namespace, field],
            intent_to_retain: true
          });
        }
      }
      return {
        id: 'mdl-id',
        format: 'mso_mdoc',
        meta: {doctype_value: docRequest.docType},
        claims
      };
    });
    const dcqlQuery = {credentials};

    // convert DCQL into presentation definition
    const groupId = globalThis.crypto.randomUUID();
    const input_descriptors = dcqlQuery.credentials.map(credential => {
      const fields = credential.claims.map(claim => {
        return {
          path: [`\$['${claim.path.join('\'][\'')}']`],
          fields: {type: 'string'}
        };
      });
      return {
        id: credential.meta.doctype_value,
        constraints: {fields},
        format: {[credential.format]: {}},
        group: [groupId]
      };
    });
    presentationDefinition = {
      id: globalThis.crypto.randomUUID(),
      input_descriptors,
      submission_requirements: [{
        rule: 'pick',
        count: 1,
        from: groupId
      }]
    };
  }

  // FIXME: this API undesirably performs full encryption, etc. so it is not
  // left to oid4-client
  /*const deviceKey = CoseKey.fromJwk(devicePrivateJwk);
  const response = await IsoMdocDcApi.createResponse({
    parsedRequest,
    documents: [{issuerSigned, deviceKey, docRequestIndex: 0}]
  }, mdocContext);
  encodedDeviceResponse = response.encode();*/

  // pick input_descriptor w/ID: `MDOC_TYPE_MDL` as needed by auth0 lib
  presentationDefinition = {
    ...presentationDefinition,
    input_descriptors: presentationDefinition.input_descriptors.filter(
      e => e.id === MDOC_TYPE_MDL)
  };
  const encodedSessionTranscript = await encodeSessionTranscript({handover});
  const deviceResponse = await DeviceResponse.from(mdoc)
    .usingPresentationDefinition(presentationDefinition)
    .usingSessionTranscriptBytes(encodedSessionTranscript)
    .authenticateWithSignature(devicePrivateJwk, 'ES256')
    .sign();
  //console.log('Device response', deviceResponse);

  const encodedDeviceResponse = deviceResponse.encode();

  const b64Mdoc = Buffer.from(encodedDeviceResponse).toString('base64');
  // console.log('device side: device response cbor', encodedDeviceResponse);
  // console.log(vpToken, 'vpToken');

  return {
    '@context': [VC_CONTEXT_2],
    id: `data:application/mdoc;base64,${b64Mdoc}`,
    type: 'EnvelopedVerifiablePresentation'
  };
}

export async function generateDeviceKeyPair() {
  // FIXME: generate new key pair each time
  const publicJwk = {
    kty: 'EC',
    x: 'QiUaYhZak1NubJEphQWmafykivrD80D2IpwqkkCU0oQ',
    y: 'sdNfR3813hzaUqF3-kWWOjI1xtSEqb93-graWFK-bA4',
    crv: 'P-256'
  };
  const privateJwk = {
    ...publicJwk,
    d: 'V729tbSdAGAL34Gqt2lGFM0Y9qrxILDUVheFduEkgFU'
  };
  return {publicJwk, privateJwk};
}

export async function issue({
  issuerPrivateJwk, issuerCertificate,
  devicePublicJwk
} = {}) {
  // parse issuer certificate chain and use it to modulate validity period
  const validityInfo = {};
  const issuerCertificateChain = [issuerCertificate].map(pem => {
    const certificate = new X509Certificate(pem);
    // limit validity period to certificate period
    const validFrom = certificate.validFromDate;
    const validUntil = certificate.validToDate;
    validityInfo.validFrom = validFrom;
    validityInfo.validUntil = validUntil;
    validityInfo.signed = validityInfo.validFrom;
    return certificate.raw;
  });

  // construct and sign mDL
  const mdocIssuer = new MDocIssuer(MDOC_TYPE_MDL, mdocContext);
  mdocIssuer.addIssuerNamespace(MDL_NAMESPACE, {
    family_name: 'FamilyName',
    given_name: 'GivenName',
    birth_date: '1990-01-01',
    age_over_21: true
  });
  const issuerSigned = await mdocIssuer.sign({
    signingKey: CoseKey.fromJwk(issuerPrivateJwk),
    certificates: issuerCertificateChain,
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: {deviceKey: DeviceKey.fromJwk(devicePublicJwk)},
    validityInfo
  });

  // issue *another* mdoc in legacy format using `@auth0/mdl`
  const document = await new Document(MDOC_TYPE_MDL)
    .addIssuerNameSpace(MDL_NAMESPACE, {
      family_name: 'FamilyName',
      given_name: 'GivenName',
      birth_date: '1990-01-01',
      age_over_21: true
    })
    .useDigestAlgorithm('SHA-256')
    .addValidityInfo({signed: new Date()})
    .addDeviceKeyInfo({deviceKey: devicePublicJwk})
    .sign({
      issuerPrivateKey: issuerPrivateJwk,
      issuerCertificate,
      kid: issuerPrivateJwk.kid,
      alg: 'ES256'
    });

  // return both legacy `mdoc` and `issuerSigned`
  return {
    mdoc: new MDoc([document]),
    issuerSigned
  };
}

export async function verifyPresentation({
  deviceResponse, handover, trustedCertificates
} = {}) {
  // uncomment to debug:
  /*const parsed = parse(deviceResponse);
  const issuerCertificate = parsed.documents?.[0]
    .issuerSigned?.issuerAuth?.certificate;
  console.log('issuer certificate', issuerCertificate);*/

  // produced on the verifier side
  const encodedSessionTranscript = await encodeSessionTranscript({handover});

  const verifier = new Verifier(trustedCertificates);
  // console.log('Getting diagnostic information...');
  // const diagnostic = await verifier.getDiagnosticInformation(
  //   deviceResponse, {encodedSessionTranscript});
  // console.debug('Diagnostic information:', diagnostic);

  try {
    const mdoc = await verifier.verify(deviceResponse, {
      encodedSessionTranscript
    });
    // console.log('Verification succeeded!');
    // console.log('Verified mdoc', mdoc);
    // console.log('DeviceSignedDocument', mdoc.documents[0]);

    // express cbor-encoded mdoc as an enveloped VC in a VP
    const encodedMdoc = mdoc.encode();
    const b64Mdoc = Buffer.from(encodedMdoc).toString('base64');
    return {
      '@context': [VC_CONTEXT_2],
      type: 'VerifiablePresentation',
      verifiableCredential: [{
        '@context': [VC_CONTEXT_2],
        id: `data:application/mdoc;base64,${b64Mdoc}`,
        type: 'EnvelopedVerifiableCredential'
      }]
    };
  } catch(err) {
    //console.error('Verification failed:', err);
    return;
  }
}

// check certificate validity window; throw if outside [notBefore, notAfter]
function _checkValidity(cert, now) {
  const date = now ?? new Date();
  const notBefore = new Date(cert.validFrom);
  const notAfter = new Date(cert.validTo);
  if(date < notBefore || date > notAfter) {
    throw new Error(
      `Certificate is not valid at ${date.toUTCString()} ` +
      `(valid ${notBefore.toUTCString()} to ${notAfter.toUTCString()})`);
  }
}

// strip undefined fields from a CoseKey JWK before passing to webcrypto
function _cleanJwk(jwk) {
  return Object.fromEntries(
    Object.entries(jwk).filter(([, v]) => v !== undefined));
}

// parse a distinguished name string into a field map; handles both
// " + " (Node.js multi-valued RDN format) and "\n" separators
function _parseDN(dn) {
  const fields = {};
  for(const part of dn.split(/\s*\+\s*|\n/)) {
    const idx = part.indexOf('=');
    if(idx === -1) {
      continue;
    }
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if(!fields[key]) {
      fields[key] = [];
    }
    fields[key].push(val);
  }
  return fields;
}
