/*!
* Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
*/
import {config} from '@bedrock/core';

export const mockData = {};

// mock product IDs and reverse lookup for service products
mockData.productIdMap = new Map([
  // edv service
  ['edv', 'urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41'],
  ['urn:uuid:dbd15f08-ff67-11eb-893b-10bf48838a41', 'edv'],
  // vc-exchanger service
  ['vc-exchanger', 'urn:uuid:146b6a5b-eade-4612-a215-1f3b5f03d648'],
  ['urn:uuid:146b6a5b-eade-4612-a215-1f3b5f03d648', 'vc-exchanger'],
  // vc-issuer service
  ['vc-issuer', 'urn:uuid:66aad4d0-8ac1-11ec-856f-10bf48838a41'],
  ['urn:uuid:66aad4d0-8ac1-11ec-856f-10bf48838a41', 'vc-issuer'],
  // vc-verifier service
  ['vc-verifier', 'urn:uuid:5dce95eb-d0e2-407d-b4ec-d3ced2f586d5'],
  ['urn:uuid:5dce95eb-d0e2-407d-b4ec-d3ced2f586d5', 'vc-verifier'],
  // webkms service
  ['webkms', 'urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41'],
  ['urn:uuid:80a82316-e8c2-11eb-9570-10bf48838a41', 'webkms']
]);

mockData.baseUrl = config.server.baseUri;

// OpenID discovery server meta data example:
// https://accounts.google.com/.well-known/openid-configuration

// `jwks_uri` example w/RSA keys:
// https://www.googleapis.com/oauth2/v3/certs

// minimal example open ID config for testing
mockData.oauth2IssuerConfigRoute = '/.well-known/oauth-authorization-server';
mockData.oauth2Config = {
  issuer: mockData.baseUrl,
  jwks_uri: `${mockData.baseUrl}/oauth2/jwks`,
  token_endpoint: `${mockData.baseUrl}/oauth2/token`
};

// Ed25519 and EC keys
mockData.ed25519KeyPair = {
  kid: '-iHGX4KWRiuX0aa3sAnhKTw7utzGI2el7HVI4LCFiJg',
  kty: 'OKP',
  crv: 'Ed25519',
  d: 'ANQCyJz3mHyJGYzvAwHlUa4pHzfMhJWSHvadUYTi7Hg',
  x: '-iHGX4KWRiuX0aa3sAnhKTw7utzGI2el7HVI4LCFiJg'
};

mockData.jwks = {
  // Ed25519 public key matches full key pair above
  keys: [{
    kid: '-iHGX4KWRiuX0aa3sAnhKTw7utzGI2el7HVI4LCFiJg',
    kty: 'OKP',
    crv: 'Ed25519',
    //d: 'ANQCyJz3mHyJGYzvAwHlUa4pHzfMhJWSHvadUYTi7Hg',
    x: '-iHGX4KWRiuX0aa3sAnhKTw7utzGI2el7HVI4LCFiJg',
    key_ops: ['verify']
  }, {
    kid: 'H6hWVHmpAG6mnCW6_Up2EYYZu-98-MK298t4LLsqGSM',
    kty: 'EC',
    crv: 'P-256',
    x: 'H6hWVHmpAG6mnCW6_Up2EYYZu-98-MK298t4LLsqGSM',
    y: 'iU2niSRdN77sFhdRvTifg4hcy4AmfsDSOND0_RHhcIU',
    //d: '25f2jge6YltyS3kdXHsm3tEEbkj_fdyC6ODJAfjgem4',
    use: 'sig'
  }, {
    kid: 'uApgIU7jCc8QRcm1iJR7AuYOCGVsTuY--6jvYCNsrY6naQ2TJETabttQSI33Tg5_',
    kty: 'EC',
    crv: 'P-384',
    x: 'uApgIU7jCc8QRcm1iJR7AuYOCGVsTuY--6jvYCNsrY6naQ2TJETabttQSI33Tg5_',
    y: 'rnavIz5-cIeuJDYzX-E4vwLRo7g2z96KBcGMaQ0V2KMvS-q8e2sZmLfL-O0kZf6v',
    //d: 'BK5RZ_7qm2JhoNAfXxW-Ka6PbAJTUaK7f2Xm-c8jBkk3dpFi2d15gl_nPHnX4Nfg',
    key_ops: ['verify']
  }]
};

mockData.credentialTemplate = `
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "id": credentialId,
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ],
    "issuanceDate": issuanceDate,
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    }
  }
`;

mockData.didAuthnCredentialTemplate = `
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      'https://www.w3.org/2018/credentials/examples/v1'
    ],
    "id": credentialId,
    "type": [
      "VerifiableCredential",
      "UniversityDegreeCredential"
    ],
    "issuanceDate": issuanceDate,
    "credentialSubject": {
      "id": didAuthn.did,
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    }
  }
`;

mockData.credentialDefinition = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/2018/credentials/examples/v1'
  ],
  type: [
    'VerifiableCredential',
    'UniversityDegreeCredential'
  ]
};

/* eslint-disable */
mockData.examplesContext = {
  // Note: minor edit to remove unused ODRL context
  "@context": {
    "ex": "https://example.org/examples#",
    "schema": "http://schema.org/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",

    "3rdPartyCorrelation": "ex:3rdPartyCorrelation",
    "AllVerifiers": "ex:AllVerifiers",
    "Archival": "ex:Archival",
    "BachelorDegree": "ex:BachelorDegree",
    "Child": "ex:Child",
    "CLCredentialDefinition2019": "ex:CLCredentialDefinition2019",
    "CLSignature2019": "ex:CLSignature2019",
    "IssuerPolicy": "ex:IssuerPolicy",
    "HolderPolicy": "ex:HolderPolicy",
    "Mother": "ex:Mother",
    "RelationshipCredential": "ex:RelationshipCredential",
    "UniversityDegreeCredential": "ex:UniversityDegreeCredential",
    "AlumniCredential": "ex:AlumniCredential",
    "DisputeCredential": "ex:DisputeCredential",
    "PrescriptionCredential": "ex:PrescriptionCredential",
    "ZkpExampleSchema2018": "ex:ZkpExampleSchema2018",

    "issuerData": "ex:issuerData",
    "attributes": "ex:attributes",
    "signature": "ex:signature",
    "signatureCorrectnessProof": "ex:signatureCorrectnessProof",
    "primaryProof": "ex:primaryProof",
    "nonRevocationProof": "ex:nonRevocationProof",

    "alumniOf": {"@id": "schema:alumniOf", "@type": "rdf:HTML"},
    "child": {"@id": "ex:child", "@type": "@id"},
    "degree": "ex:degree",
    "degreeType": "ex:degreeType",
    "degreeSchool": "ex:degreeSchool",
    "college": "ex:college",
    "name": {"@id": "schema:name", "@type": "rdf:HTML"},
    "givenName": "schema:givenName",
    "familyName": "schema:familyName",
    "parent": {"@id": "ex:parent", "@type": "@id"},
    "referenceId": "ex:referenceId",
    "documentPresence": "ex:documentPresence",
    "evidenceDocument": "ex:evidenceDocument",
    "spouse": "schema:spouse",
    "subjectPresence": "ex:subjectPresence",
    "verifier": {"@id": "ex:verifier", "@type": "@id"},
    "currentStatus": "ex:currentStatus",
    "statusReason": "ex:statusReason",
    "prescription": "ex:prescription"
  }
};
/* eslint-enable */
