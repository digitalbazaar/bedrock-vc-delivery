/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
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
    oidc4vci: {
      title: 'OIDC4VCI Exchange options',
      type: 'object',
      additionalProperties: false,
      properties: {
        preAuthorizedCode: {
          type: 'string'
        }
      }
    }
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
