/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import assert from 'assert-plus';
import {logger} from './logger.js';
import {parseLocalId} from './helpers.js';

const {util: {BedrockError}} = bedrock;

/* Note: Exchanges either have TTLs and can be "completed" or they persist
and never "complete" nor expire.

Exchanges are always in one of three states: `pending`, `complete`, or
`invalid`. They can only transistion from `pending` to `complete` or from
`complete` to `invalid`.

If an exchange is marked as complete, any attempt to mark it complete again
will result in an action, as specified in the exchange record, being taken
such as auto-revocation or notification.

Each pending exchange may include optionally encrypted VCs for pickup and / or
VC templates and required variables (which may come from other VCs) that must
be provided to populate those templates. If any templates are provided, then
a capability to issue the VC must also be provided. If any VCs are to be
provided during the exchange a capability to verify them must be provided. */

const COLLECTION_NAME = 'vc-exchange';

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections([COLLECTION_NAME]);

  await database.createIndexes([{
    // cover exchange queries by exchanger ID + exchange ID
    collection: COLLECTION_NAME,
    fields: {localExchangerId: 1, 'exchange.id': 1},
    options: {unique: true}
  }, {
    // expire exchanges based on `expires` field
    collection: COLLECTION_NAME,
    fields: {'meta.expires': 1},
    options: {
      partialFilterExpression: {
        'meta.expires': {$exists: true}
      },
      unique: false,
      expireAfterSeconds: 0
    }
  }]);
});

/**
 * Inserts an exchange record.
 *
 * @param {object} options - The options to use.
 * @param {string} options.exchangerId - The ID of the exchanger that the
 *   exchange is associated with.
 * @param {object} options.exchange - The exchange to insert.
 *
 * @returns {Promise<object>} Resolves to the database record.
 */
export async function insert({exchangerId, exchange}) {
  assert.string(exchangerId, 'exchangerId');
  assert.object(exchange, 'exchange');
  assert.string(exchange.id, 'exchange.id');
  // optional time to live in seconds
  assert.optionalNumber(exchange.ttl);
  // optional variables to use in VC templates
  assert.optionalObject(exchange.variables);
  // optional current step in the exchange
  assert.optionalString(exchange.step);

  // build exchange record
  const now = Date.now();
  const meta = {created: now, updated: now};
  if(exchange.ttl !== undefined) {
    // TTL is in seconds
    meta.expires = new Date(now + exchange.ttl * 1000);
  }
  const {localId: localExchangerId} = parseLocalId({id: exchangerId});
  const record = {
    localExchangerId,
    meta,
    // possible states are: `pending`, `complete`, or `invalid`
    exchange: {...exchange, state: 'pending'}
  };

  // insert the exchange and get the updated record
  try {
    const collection = database.collections[COLLECTION_NAME];
    await collection.insertOne(record);
    return record;
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw e;
    }
    throw new BedrockError('Duplicate document.', {
      name: 'DuplicateError',
      details: {
        public: true,
        httpStatusCode: 409
      },
      cause: e
    });
  }
}

/**
 * Gets an exchange record.
 *
 * @param {object} options - The options to use.
 * @param {string} options.exchangerId - The ID of the exchanger that the
 *   exchange is associated with.
 * @param {string} options.id - The ID of the exchange to retrieve.
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<object | ExplainObject>} Resolves with the record that
 *   matches the query or an ExplainObject if `explain=true`.
 */
export async function get({exchangerId, id, explain = false} = {}) {
  assert.string(exchangerId, 'exchangerId');
  assert.string(id, 'id');

  const {localId: localExchangerId} = parseLocalId({id: exchangerId});
  const collection = database.collections[COLLECTION_NAME];
  const query = {
    localExchangerId,
    'exchange.id': id,
    // treat exchange as not found if invalid
    'exchange.state': {$ne: 'invalid'}
  };
  const projection = {_id: 0, exchange: 1, meta: 1};

  if(explain) {
    // 'find().limit(1)' is used here because 'findOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await collection.find(query, {projection}).limit(1);
    return cursor.explain('executionStats');
  }

  const record = await collection.findOne(query, {projection});
  if(!record) {
    throw new BedrockError('Exchange not found.', {
      name: 'NotFoundError',
      details: {
        exchanger: exchangerId,
        exchange: id,
        httpStatusCode: 404,
        public: true
      }
    });
  }

  return record;
}

/**
 * Marks an exchange as complete.
 *
 * @param {object} options - The options to use.
 * @param {string} options.exchangerId - The ID of the exchanger the exchange
 *   is associated with.
 * @param {object} options.id - The ID of the exchange to mark as complete.
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<boolean | ExplainObject>} Resolves with `true` on update
 *   success or an ExplainObject if `explain=true`.
 */
export async function complete({exchangerId, id, explain = false} = {}) {
  assert.string(exchangerId, 'exchangerId');
  assert.string(id, 'id');

  // build update
  const now = Date.now();
  const update = {
    $set: {
      'exchange.state': 'complete',
      'meta.updated': now
    }
  };

  const {localId: localExchangerId} = parseLocalId({id: exchangerId});

  const collection = database.collections[COLLECTION_NAME];
  const query = {
    localExchangerId,
    'exchange.id': id,
    // previous state must be `pending` in order to change to `complete`
    'exchange.state': 'pending'
  };

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await collection.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  try {
    const result = await collection.updateOne(query, update);
    if(result.modifiedCount > 0) {
      // document modified: success
      return true;
    }
  } catch(e) {
    throw new BedrockError('Could not complete exchange.', {
      name: 'OperationError',
      details: {
        public: true,
        httpStatusCode: 500
      },
      cause: e
    });
  }

  // if no document was matched, try to get an existing exchange; if the
  // exchange does not exist, a not found error will be automatically thrown
  const record = await get({exchangerId, id});

  /* Note: Here the exchange *does* exist, but was already completed. This is
  an error condition that must result in invalidating the exchange. */

  // invalidate exchange, but do not throw any error to client; only log it
  _invalidateExchange({record}).catch(
    error => logger.error(`Could not invalidate exchange "${id}".`, {error}));

  // throw duplicate completed exchange error
  throw new BedrockError('Could not complete exchange; already completed.', {
    name: 'DuplicateError',
    details: {
      public: true,
      // this is a client-side conflict error
      httpStatusCode: 409
    }
  });
}

async function _invalidateExchange({record}) {
  try {
    // mark exchange invalid, but do not throw any error to client; only log it
    await _markExchangeInvalid({record});
  } catch(error) {
    logger.error(
      `Could not mark exchange "${record.exchange.id}" invalid.`, {error});
  }

  /* Perform auto-revocation of the VCs or notification (the action to take
  is specified in the exchange record). */
  // FIXME: handle auto-revocation / notification in background; do not throw
  // errors to client
}

async function _markExchangeInvalid({record}) {
  const now = Date.now();

  // mark exchange invalid
  try {
    const query = {
      localExchangerId: record.localExchangerId,
      'exchange.id': record.exchange.id
    };
    const update = {
      $set: {
        'exchange.state': 'invalid',
        'meta.updated': now,
        // allow up to 3 days to resolve invalid exchange issues
        // (86400 seconds in 24 hours)
        'meta.expires': new Date(now + 86400 * 3 * 1000)
      }
    };
    const collection = database.collections[COLLECTION_NAME];
    const result = await collection.updateOne(query, update);
    if(result.modifiedCount > 0) {
      // document modified: success
      return true;
    }
  } catch(e) {
    throw new BedrockError('Could not mark exchange invalid.', {
      name: 'OperationError',
      details: {
        public: true,
        httpStatusCode: 500
      },
      cause: e
    });
  }
}

/**
 * An object containing information on the query plan.
 *
 * @typedef {object} ExplainObject
 */
