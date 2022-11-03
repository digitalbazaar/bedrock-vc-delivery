/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {schemas} from '@bedrock/validation';

const oidc4vciExchangeOptions = {
  title: 'OIDC4VCI Exchange options',
  type: 'object',
  additionalProperties: false,
  properties: {
    preAuthorizedCode: {
      type: 'string'
    },
    oauth2: {
      title: 'OIDC4VCI Exchange OAuth2 Options',
      type: 'object',
      additionalProperties: false,
      required: ['keyPair'],
      properties: {
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
    oidc4vci: oidc4vciExchangeOptions
  }
};

const credentialTemplate = {
  title: 'Credential Template',
  type: 'object',
  required: ['type', 'template'],
  additionalProperties: false,
  properties: {
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
  items: credentialTemplate
};

const step = {
  title: 'Exchange Step',
  type: 'object',
  additionalProperties: false,
  properties: {
    createChallenge: {
      type: 'boolean'
    },
    verifiablePresentationRequest: {
      type: 'object'
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
    // FIXME: add jsonata template to convert VPR or
    // `jwtDidProofRequest` to more variables to be
    // used when issuing VCs
    // FIXME: `nextStep` feature not yet implemented
    // nextStep: {
    //   type: 'string'
    // }
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

export const oidc4vciCredentialBody = {
  title: 'OIDC4VCI Credential Request',
  type: 'object',
  additionalProperties: false,
  required: ['type', 'format'],
  properties: {
    type: {
      type: 'string'
    },
    format: {
      type: 'string',
      enum: ['ldp_vc']
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

export const oidc4vciTokenBody = {
  title: 'OIDC4VCI Token Request',
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
