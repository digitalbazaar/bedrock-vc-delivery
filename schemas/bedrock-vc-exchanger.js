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
    /* Note: If template types other than `jsonata` are supported in the
    future, then `template` may need to support `string`. */
    template: {
      type: 'object',
      additionalProperties: true
    }
  }
};

export const credentialTemplates = {
  title: 'Credential Templates',
  type: 'array',
  minItems: 1,
  items: credentialTemplate
};
