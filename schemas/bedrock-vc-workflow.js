/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {MAX_ISSUER_INSTANCES} from '../lib/constants.js';
import {schemas} from '@bedrock/validation';

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
      minItems: 2,
      item: {
        type: 'string'
      }
    },
    // allow `types` to be flexible for OID4VCI draft 20 implementers
    types: {
      type: 'array',
      minItems: 2,
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
      enum: ['ldp_vc', 'jwt_vc_json-ld']
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
        keyPair: {
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
        },
        maxClockSkew: {
          type: 'number'
        }
      }
    }
  }
};

export const createExchangeBody = {
  title: 'Create Exchange',
  type: 'object',
  additionalProperties: false,
  properties: {
    ttl: {
      type: 'number'
    },
    variables: {
      type: 'object',
      additionalProperties: true
    },
    openId: openIdExchangeOptions
  }
};

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
  required: ['zcapReferenceIds'],
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
        'createChallenge',
        'verifiablePresentationRequest',
        'jwtDidProofRequest',
        'nextStep',
        'openId'
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
    createChallenge: {
      type: 'boolean'
    },
    verifiablePresentationRequest: {
      type: 'object'
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
    stepTemplate: typedTemplate,
    // required to support OID4VP (but can be provided by step template instead)
    openId: {
      type: 'object',
      additionalProperties: false,
      // an authorization request or a directive to create one can be used,
      // but not both
      oneOf: [{
        required: ['createAuthorizationRequest'],
        // cannot also use `authorizationRequest
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
      verifiablePresentation: schemas.verifiablePresentation()
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
      enum: ['ldp_vc', 'jwt_vc_json-ld']
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
    required: ['presentation_submission', 'vp_token'],
    properties: {
      // is a JSON string in the x-www-form-urlencoded body
      presentation_submission: {
        type: 'string'
      },
      // is a JSON string in the x-www-form-urlencoded body
      vp_token: {
        type: 'string'
      },
      state: {
        type: 'string'
      }
    }
  };
}
