/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
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
