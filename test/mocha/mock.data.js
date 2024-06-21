/*!
* Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
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

mockData.alumniCredentialTemplate = `
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "id": credentialId,
    "type": [
      "VerifiableCredential",
      "AlumniCredential"
    ],
    "issuanceDate": issuanceDate,
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "alumniOf": {
        "name": "Example University"
      }
    }
  }
`;

mockData.credentialRequestTemplate = `
  {
    "options": {
      "credentialId": credentialId
    },
    "credential": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
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
  }
`;

mockData.genericCredentialRequestTemplate = `$eval(credentialRequest)`;
mockData.genericCredentialTemplate = `$eval(vc)`;

/* eslint-disable */
mockData.prcCredentialTemplate = `
  {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/citizenship/v1"
    ],
    "id": credentialId,
    "type": [
      "VerifiableCredential",
      "PermanentResidentCard"
    ],
    "identifier": "83627465",
    "name": "Permanent Resident Card",
    "description": "Government of Utopia Permanent Resident Card.",
    "issuanceDate": issuanceDate,
    "credentialSubject": {
      "id": "did:example:b34ca6cd37bbf23",
      "type": [
        "PermanentResident",
        "Person"
      ],
      "givenName": "JANE",
      "familyName": "SMITH",
      "gender": "Female",
      "image": "data:image/png;base64,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",
      "residentSince": "2015-01-01",
      "lprCategory": "C09",
      "lprNumber": "999-999-999",
      "commuterClassification": "C1",
      "birthCountry": "Arcadia",
      "birthDate": "1978-07-17"
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
      "id": results.didAuthn.did,
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

mockData.prcCredentialDefinition = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/citizenship/v1'
  ],
  type: [
    'VerifiableCredential',
    'PermanentResidentCard'
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

/* eslint-disable */
mockData.prcCredentialContext = {
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "name": "http://schema.org/name",
    "description": "http://schema.org/description",
    "identifier": "http://schema.org/identifier",
    "image": {
      "@id": "http://schema.org/image",
      "@type": "@id"
    },
    "PermanentResidentCard": {
      "@id": "https://w3id.org/citizenship#PermanentResidentCard",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "description": "http://schema.org/description",
        "name": "http://schema.org/name",
        "identifier": "http://schema.org/identifier",
        "image": {
          "@id": "http://schema.org/image",
          "@type": "@id"
        }
      }
    },
    "PermanentResident": {
      "@id": "https://w3id.org/citizenship#PermanentResident",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "ctzn": "https://w3id.org/citizenship#",
        "schema": "http://schema.org/",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "birthCountry": "ctzn:birthCountry",
        "birthDate": {
          "@id": "schema:birthDate",
          "@type": "xsd:dateTime"
        },
        "commuterClassification": "ctzn:commuterClassification",
        "familyName": "schema:familyName",
        "gender": "schema:gender",
        "givenName": "schema:givenName",
        "lprCategory": "ctzn:lprCategory",
        "lprNumber": "ctzn:lprNumber",
        "residentSince": {
          "@id": "ctzn:residentSince",
          "@type": "xsd:dateTime"
        }
      }
    },
    "Person": "http://schema.org/Person"
  }
};
/* eslint-enable */
