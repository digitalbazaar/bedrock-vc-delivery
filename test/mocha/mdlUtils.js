/*
 * Copyright (c) 2025-2026 Digital Bazaar, Inc.
 */
import {DeviceResponse, Document, MDoc, /*parse,*/ Verifier} from '@auth0/mdl';
import {exportJWK, importX509} from 'jose';
import {webcrypto, X509Certificate} from 'node:crypto';
import {CoseKey} from '@owf/mdoc';
import {oid4vp} from '@digitalbazaar/oid4-client';

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const MDL_NAMESPACE = 'org.iso.18013.5.1';
const MDOC_TYPE_MDL = `${MDL_NAMESPACE}.mDL`;

const {encodeSessionTranscript} = oid4vp.mdl;

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
      async verify({sign1, key}) {
        const cryptoKey = await webcrypto.subtle.importKey(
          'jwk', _cleanJwk(key.jwk),
          {name: 'ECDSA', namedCurve: 'P-256'},
          false, ['verify']);
        return webcrypto.subtle.verify(
          {name: 'ECDSA', hash: 'SHA-256'}, cryptoKey,
          sign1.signature, sign1.toBeSigned);
      }
    }
  },
  x509: {
    getIssuerNameField({certificate, field}) {
      const cert = new X509Certificate(certificate);
      return _parseDN(cert.issuer)[field] ?? [];
    },
    async getPublicKey({certificate, alg}) {
      const cert = new X509Certificate(certificate);
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
      const lastCert = chain[chain.length - 1];
      const isTrusted = trusted.some(t => {
        try {
          return lastCert.verify(t.publicKey) && lastCert.checkIssued(t);
        } catch(e) {
          return false;
        }
      });
      if(!isTrusted) {
        throw new Error(
          'No trusted certificate was found while validating the X.509 chain');
      }
      _checkValidity(lastCert, now);
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

export async function createPresentation({
  presentationDefinition,
  mdoc, handover, devicePrivateJwk
} = {}) {
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

  // FIXME: define a base64url-encoded mdl vp token mime type?
  const encodedDeviceResponse = deviceResponse.encode();
  const vpToken = Buffer.from(encodedDeviceResponse).toString('base64url');
  // console.log('device side: device response cbor', encodedDeviceResponse);
  // console.log(vpToken, 'vpToken');

  return {
    '@context': [VC_CONTEXT_2],
    id: `data:application/mdl-vp-token,${vpToken}`,
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
  return new MDoc([document]);
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
    const b64Mdl = Buffer.from(encodedMdoc).toString('base64');
    return {
      '@context': [VC_CONTEXT_2],
      type: 'VerifiablePresentation',
      verifiableCredential: [{
        id: `data:application/mdl;base64,${b64Mdl}`,
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
