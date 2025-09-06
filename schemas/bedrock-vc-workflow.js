/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {MAX_ISSUER_INSTANCES} from '../lib/constants.js';
import {schemas} from '@bedrock/validation';

const VC_CONTEXT_1 = 'https://www.w3.org/2018/credentials/v1';
const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

const vcContext = {
  type: 'array',
  minItems: 1,
  // the first context must be the VC context
  items: [{
    oneOf: [{
      const: VC_CONTEXT_1
    }, {
      const: VC_CONTEXT_2
    }]
  }],
  // additional contexts maybe strings or objects
  additionalItems: {
    anyOf: [{type: 'string'}, {type: 'object'}]
  }
};

const vcContext2StringOrArray = {
  oneOf: [{
    const: VC_CONTEXT_2
  }, {
    type: 'array',
    minItems: 1,
    // the first context must be the VC 2.0 context
    items: [{
      const: VC_CONTEXT_2
    }],
    // additional contexts maybe strings or objects
    additionalItems: {
      anyOf: [{type: 'string'}, {type: 'object'}]
    }
  }]
};

function idOrObjectWithId() {
  return {
    title: 'identifier or an object with an id',
    anyOf: [
      schemas.identifier(),
      {
        type: 'object',
        required: ['id'],
        additionalProperties: true,
        properties: {id: schemas.identifier()}
      }
    ]
  };
}

function verifiableCredential() {
  return {
    title: 'Verifiable Credential',
    type: 'object',
    required: [
      '@context',
      'credentialSubject',
      'issuer',
      'type'
    ],
    additionalProperties: true,
    properties: {
      '@context': vcContext,
      credentialSubject: {
        anyOf: [
          {type: 'object'},
          {type: 'array', minItems: 1, items: {type: 'object'}}
        ]
      },
      id: {
        type: 'string'
      },
      issuer: idOrObjectWithId(),
      type: {
        type: 'array',
        minItems: 1,
        // this first type must be VerifiableCredential
        items: [
          {const: 'VerifiableCredential'},
        ],
        // additional types must be strings
        additionalItems: {
          type: 'string'
        }
      },
      proof: schemas.proof()
    }
  };
}

const envelopedVerifiableCredential = {
  title: 'Enveloped Verifiable Credential',
  type: 'object',
  additionalProperties: true,
  properties: {
    '@context': vcContext2StringOrArray,
    id: {
      type: 'string'
    },
    type: {
      const: 'EnvelopedVerifiableCredential'
    }
  },
  required: [
    '@context',
    'id',
    'type'
  ]
};

const envelopedVerifiablePresentation = {
  title: 'Enveloped Verifiable Presentation',
  type: 'object',
  additionalProperties: true,
  properties: {
    '@context': vcContext2StringOrArray,
    id: {
      type: 'string'
    },
    type: {
      const: 'EnvelopedVerifiablePresentation'
    }
  },
  required: [
    '@context',
    'id',
    'type'
  ]
};

const jwkKeyPair = {
  type: 'object',
  additionalProperties: false,
  required: ['privateKeyJwk', 'publicKeyJwk'],
  properties: {
    privateKeyJwk: {
      type: 'object'
    },
    publicKeyJwk: {
      type: 'object'
    }
  }
};

export function verifiablePresentation() {
  return {
    title: 'Verifiable Presentation',
    type: 'object',
    required: ['@context', 'type'],
    additionalProperties: true,
    properties: {
      '@context': vcContext,
      id: {
        type: 'string'
      },
      type: {
        type: 'array',
        minItems: 1,
        // this first type must be VerifiablePresentation
        items: [
          {const: 'VerifiablePresentation'},
        ],
        // additional types must be strings
        additionalItems: {
          type: 'string'
        }
      },
      verifiableCredential: {
        anyOf: [
          verifiableCredential(),
          envelopedVerifiableCredential, {
            type: 'array',
            minItems: 1,
            items: {
              anyOf: [verifiableCredential(), envelopedVerifiableCredential]
            }
          }
        ]
      },
      holder: idOrObjectWithId(),
      proof: schemas.proof()
    }
  };
}

const credentialDefinition = {
  title: 'OID4VCI Verifiable Credential Definition',
  type: 'object',
  additionalProperties: false,
  required: ['@context', 'type'],
  properties: {
    '@context': {
      type: 'array',
      minItems: 1,
      item: {
        type: 'string'
      }
    },
    type: {
      type: 'array',
      minItems: 1,
      item: {
        type: 'string'
      }
    },
    // allow `types` to be flexible for OID4VCI draft 20 implementers
    types: {
      type: 'array',
      minItems: 1,
      item: {
        type: 'string'
      }
    }
  }
};

const expectedCredentialRequest = {
  type: 'object',
  additionalProperties: false,
  required: ['credential_definition'],
  properties: {
    credential_definition: credentialDefinition,
    format: {
      type: 'string',
      enum: ['di_vc', 'ldp_vc', 'jwt_vc_json-ld', 'jwt_vc_json']
    }
  }
};

const openIdExchangeOptions = {
  title: 'OpenID Exchange options',
  type: 'object',
  additionalProperties: false,
  required: ['expectedCredentialRequests', 'preAuthorizedCode', 'oauth2'],
  properties: {
    expectedCredentialRequests: {
      title: 'OpenID Expected Credential Requests',
      type: 'array',
      minItems: 1,
      items: expectedCredentialRequest
    },
    preAuthorizedCode: {
      type: 'string'
    },
    oauth2: {
      title: 'OpenID Exchange OAuth2 Options',
      type: 'object',
      additionalProperties: false,
      oneOf: [{
        required: ['keyPair']
      }, {
        required: ['generateKeyPair']
      }],
      properties: {
        generateKeyPair: {
          type: 'object',
          additionalProperties: false,
          required: ['algorithm'],
          properties: {
            algorithm: {
              enum: ['EdDSA', 'ES256', 'ES256K', 'ES384']
            }
          }
        },
        keyPair: jwkKeyPair,
        maxClockSkew: {
          type: 'number'
        }
      }
    }
  }
};

export function createExchangeBody() {
  return {
    title: 'Create Exchange',
    type: 'object',
    additionalProperties: false,
    // optionally use either `expires` or `ttl`, but NOT both
    not: {required: ['ttl', 'expires']},
    properties: {
      ttl: {
        type: 'number'
      },
      expires: schemas.w3cDateTime(),
      variables: {
        type: 'object',
        additionalProperties: true
      },
      openId: openIdExchangeOptions
    }
  };
}

const typedTemplate = {
  title: 'Typed Template',
  type: 'object',
  required: ['type', 'template'],
  additionalProperties: false,
  properties: {
    id: {
      type: 'string'
    },
    type: {
      type: 'string',
      enum: ['jsonata']
    },
    template: {
      type: 'string'
    }
  }
};

export const credentialTemplates = {
  title: 'Credential Templates',
  type: 'array',
  minItems: 1,
  items: typedTemplate
};

// to be updated in specific locations with `properties` and `required`
const zcapReferenceIds = {
  title: 'Authorization Capability Reference IDs',
  type: 'object',
  additionalProperties: false
};

const vcFormats = {
  title: 'Verifiable Credential formats',
  type: 'array',
  minItems: 1,
  items: {
    type: 'string'
  }
};

const issuerInstance = {
  title: 'Issuer Instance',
  type: 'object',
  required: ['supportedFormats', 'zcapReferenceIds'],
  additionalProperties: false,
  properties: {
    id: {
      type: 'string'
    },
    supportedFormats: vcFormats,
    zcapReferenceIds: {
      ...zcapReferenceIds,
      required: ['issue'],
      properties: {
        issue: {
          type: 'string'
        }
      }
    }
  }
};

export const issuerInstances = {
  title: 'Issuer Instances',
  type: 'array',
  minItems: 1,
  maxItems: MAX_ISSUER_INSTANCES,
  items: issuerInstance
};

const issueRequestParameters = {
  title: 'Issue Request Parameters',
  type: 'object',
  oneOf: [{
    required: ['credentialTemplateId']
  }, {
    required: ['credentialTemplateIndex']
  }],
  additionalProperties: false,
  properties: {
    credentialTemplateId: {
      type: 'string'
    },
    credentialTemplateIndex: {
      type: 'number'
    },
    // optionally specify different variables
    variables: {
      oneOf: [{type: 'string'}, {type: 'object'}]
    }
  }
};

export function inviteResponseBody() {
  return {
    title: 'Invite Response',
    type: 'object',
    additionalProperties: false,
    required: ['url', 'purpose'],
    properties: {
      url: {
        type: 'string'
      },
      purpose: {
        type: 'string'
      },
      referenceId: {
        type: 'string'
      }
    }
  };
}

const oid4vpClientProfile = {
  title: 'OID4VP Client Profile',
  type: 'object',
  additionalProperties: false,
  // an authorization request or a directive to create one can be used,
  // but not both
  oneOf: [{
    required: ['createAuthorizationRequest'],
    // cannot also use `authorizationRequest`
    not: {
      required: ['authorizationRequest']
    }
  }, {
    required: ['authorizationRequest'],
    // cannot also use `createAuthorizationRequest`
    not: {
      required: ['createAuthorizationRequest']
    }
  }],
  properties: {
    // value is name of variable to store the created authz request in
    createAuthorizationRequest: {
      type: 'string'
    },
    // ... or full authz request to use
    authorizationRequest: {
      type: 'object'
    },
    // optional properties that will be used as overrides in any authz request
    client_id: {type: 'string'},
    client_id_scheme: {type: 'string'},
    client_metadata: {type: 'object'},
    nonce: {type: 'string'},
    presentation_definition: {type: 'object'},
    response_mode: {type: 'string'},
    response_uri: {type: 'string'},
    // optional parameters for signing authorization requests
    authorizationRequestSigningParameters: {
      type: 'object',
      required: ['x5c'],
      additionalProperties: false,
      properties: {
        x5c: {
          type: 'array',
          minItems: 1,
          items: {
            type: 'string'
          }
        }
      }
    },
    // optional protocol URL parameters
    protocolUrlParameters: {
      type: 'object',
      required: ['name', 'scheme'],
      additionalProperties: false,
      properties: {
        name: {
          type: 'string'
        },
        scheme: {
          type: 'string'
        }
      }
    },
    // optional references to any zcaps for any purpose
    zcapReferenceIds: {
      ...zcapReferenceIds,
      required: ['signAuthorizationRequest'],
      properties: {
        signAuthorizationRequest: {
          type: 'string'
        }
      }
    }
  }
};

export const oid4vpClientProfiles = {
  title: 'OID4VP Client Profiles',
  type: 'object',
  additionalProperties: false,
  patternProperties: {
    '^.*$': oid4vpClientProfile
  }
};

const step = {
  title: 'Exchange Step',
  type: 'object',
  minProperties: 1,
  additionalProperties: false,
  // step can either use a template so it will be generated using variables
  // associated with the exchange, or static values can be provided
  oneOf: [{
    // `stepTemplate` must be present and nothing else
    required: ['stepTemplate'],
    not: {
      required: [
        'allowUnprotectedPresentation',
        'callback',
        'createChallenge',
        'issueRequests',
        'jwtDidProofRequest',
        'nextStep',
        'openId',
        'presentationSchema',
        'verifiablePresentationRequest'
      ]
    }
  }, {
    // anything except `stepTemplate` can be used
    not: {
      required: ['stepTemplate']
    }
  }],
  properties: {
    allowUnprotectedPresentation: {
      type: 'boolean'
    },
    callback: {
      type: 'object',
      required: ['url'],
      additionalProperties: false,
      properties: {
        url: {
          type: 'string'
        }
      }
    },
    createChallenge: {
      type: 'boolean'
    },
    issueRequests: {
      type: 'array',
      minItems: 0,
      items: issueRequestParameters
    },
    jwtDidProofRequest: {
      type: 'object',
      additionalProperties: false,
      properties: {
        acceptedMethods: {
          title: 'Accepted DID Methods',
          type: 'array',
          minItems: 1,
          items: {
            title: 'Accepted DID Method',
            type: 'object',
            additionalProperties: false,
            properties: {
              method: {
                type: 'string'
              }
            }
          }
        },
        allowedAlgorithms: {
          title: 'Allowed JWT Algorithms',
          type: 'array',
          minItems: 1,
          items: {
            type: 'string'
          }
        }
      }
    },
    nextStep: {
      type: 'string'
    },
    // required to support OID4VP (but can be provided by step template instead)
    openId: {
      // either a single top-level client profile is specified here or
      // `clientProfiles` is specified with nested client profiles
      oneOf: [{
        oid4vpClientProfile
      }, {
        type: 'object',
        required: ['clientProfiles'],
        additionalProperties: false,
        properties: {
          clientProfiles: oid4vpClientProfiles
        }
      }]
    },
    presentationSchema: {
      type: 'object',
      required: ['type', 'jsonSchema'],
      additionalProperties: false,
      properties: {
        type: {
          type: 'string'
        },
        jsonSchema: {
          type: 'object'
        }
      }
    },
    stepTemplate: typedTemplate,
    verifiablePresentationRequest: {
      type: 'object'
    },
    verifyPresentationOptions: {
      type: 'object',
      properties: {
        checks: {
          type: 'object'
        }
      },
      additionalProperties: true
    },
    verifyPresentationResultSchema: {
      type: 'object',
      required: ['type', 'jsonSchema'],
      additionalProperties: false,
      properties: {
        type: {
          type: 'string'
        },
        jsonSchema: {
          type: 'object'
        }
      }
    }
  }
};

export const steps = {
  title: 'Exchange Steps',
  type: 'object',
  additionalProperties: false,
  patternProperties: {
    '^.*$': step
  }
};

export const initialStep = {
  title: 'Initial Exchange Step',
  type: 'string'
};

export function useExchangeBody() {
  return {
    title: 'Use Exchange',
    type: 'object',
    additionalProperties: false,
    properties: {
      verifiablePresentation: {
        anyOf: [
          envelopedVerifiablePresentation,
          verifiablePresentation()
        ]
      }
    }
  };
}

const openIdCredentialRequest = {
  title: 'OpenID Credential Request',
  type: 'object',
  additionalProperties: false,
  required: ['credential_definition', 'format'],
  properties: {
    credential_definition: credentialDefinition,
    format: {
      type: 'string',
      enum: ['di_vc', 'ldp_vc', 'jwt_vc_json-ld', 'jwt_vc_json']
    },
    did: {
      type: 'string'
    },
    proof: {
      title: 'DID Authn Proof JWT',
      type: 'object',
      additionalProperties: false,
      required: ['proof_type', 'jwt'],
      properties: {
        proof_type: {
          type: 'string',
          enum: ['jwt']
        },
        jwt: {
          type: 'string'
        }
      }
    }
  }
};

export const openIdCredentialBody = openIdCredentialRequest;

export const openIdBatchCredentialBody = {
  title: 'OpenID Batch Credential Request',
  type: 'object',
  additionalProperties: false,
  required: ['credential_requests'],
  properties: {
    credential_requests: {
      title: 'OpenID Credential Requests',
      type: 'array',
      minItems: 1,
      items: openIdCredentialRequest
    }
  }
};

export const openIdTokenBody = {
  title: 'OpenID Token Request',
  type: 'object',
  additionalProperties: false,
  required: ['grant_type'],
  properties: {
    grant_type: {
      type: 'string'
    },
    'pre-authorized_code': {
      type: 'string'
    },
    // FIXME: there is no implementation for using these fields yet:
    // user_pin: {
    //   type: 'string'
    // },
    // // params for `authorization_code` grant type
    // code: {
    //   type: 'string'
    // },
    // verifier: {
    //   type: 'string'
    // },
    // redirect_uri: {
    //   type: 'string'
    // }
  }
};

const presentationDescriptor = {
  title: 'Presentation Submission Descriptor',
  type: 'object',
  additionalProperties: false,
  required: ['id', 'format', 'path'],
  properties: {
    id: {
      type: 'string'
    },
    format: {
      type: 'string'
    },
    path: {
      type: 'string'
    },
    path_nested: {
      type: 'object'
    }
  }
};

export const presentationSubmission = {
  title: 'Presentation Submission',
  type: 'object',
  additionalProperties: false,
  required: ['id', 'definition_id', 'descriptor_map'],
  properties: {
    id: {
      type: 'string'
    },
    definition_id: {
      type: 'string'
    },
    descriptor_map: {
      title: 'Presentation Submission Descriptor Map',
      type: 'array',
      minItems: 0,
      items: presentationDescriptor
    }
  }
};

export function openIdAuthorizationResponseBody() {
  return {
    title: 'OID4VP Authorization Response',
    type: 'object',
    additionalProperties: false,
    oneOf: [{
      // for response_mode == 'direct_post'
      required: ['presentation_submission', 'vp_token'],
      // cannot also use `response`
      not: {
        required: ['response']
      }
    }, {
      // for response_mode == 'direct_post.jwt'
      required: ['response'],
      // cannot also use any other params
      not: {
        required: ['presentation_submission', 'vp_token', 'state']
      }
    }],
    properties: {
      // is a JSON string in the x-www-form-urlencoded body
      presentation_submission: {
        type: 'string'
      },
      // is a JSON-encoded string or object in the x-www-form-urlencoded body
      /* Note: This can also be a simple base64url string for
      backwards/forwards compatibility. While submitting VPs directly as
      JSON objects has never changed in the OID4* specs, submitting VPs that
      are wrapped in some envelope that is expressed as a string (e.g., a JWT)
      has changed back and forth throughout the draft history. Sometimes these
      vp_tokens are required to be JSON-encoded strings other times non-JSON
      strings, i.e., no "extra/JSON quotes" around the string value inside the
      x-www-form-urlencoded field value delimiting quotes. For example,
      both of these:

      `...&vp_token="non-string JSON"`
      `...&vp_token="\"JSON string\""`

      are accepted for these reasons. */
      vp_token: {
        type: 'string'
      },
      response: {
        // must be an encrypted JWT
        type: 'string'
      },
      state: {
        type: 'string'
      }
    }
  };
}
