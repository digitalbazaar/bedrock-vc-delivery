/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
export const createExchangeBody = {
  title: 'Create Exchange',
  type: 'object',
  additionalProperties: false,
  properties: {
    variables: {
      type: 'object',
      additionalProperties: true
    }
  }
};
