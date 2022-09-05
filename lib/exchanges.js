/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import {assert128BitId, parseLocalId} from '../helpers.js';
import assert from 'assert-plus';

const {config} = bedrock;
const {util: {BedrockError}} = bedrock;

// FIXME: create storage API for exchanges; each has a TTL; that TTL is short
// ...prior to the exchange getting used, but once used, the exchange record
// ...is marked as used and the TTL is extended to some other specified period
// ...of time; if any attempt is made to use the exchange again after it has
// ...been used then an auto-revocation or notification (as specified in the
// ...exchange record) is executed
// FIXME: each pending exchange may include optionally encrypted VCs for
// ...pickup and / or VC templates and required VCs that must be provided
// ...to populate those templates
// ...if any templates are provided, then the ability to issue the VC must also
// ...be provided; in version 1, this may be a reference to a zcap and the
// ...the zcap client to invoke it -- which presumes installation on some
// ...service with those capabilities as opposed to an external service config

const COLLECTION_NAME = 'vc-exchange';

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections([COLLECTION_NAME]);

  await database.createIndexes([{
    // cover exchange queries by exchanger ID + exchange ID
    collection: COLLECTION_NAME,
    fields: {localExchangerId: 1, 'exchange.id': 1},
    options: {unique: true, background: false}
  }, {
    // expire exchanges based on `expires` field
    collection: COLLECTION_NAME,
    fields: {'exchange.expires': 1},
    options: {
      unique: false,
      background: false,
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
  assert128BitId(exchange.id);
  // FIXME: set `exchange.complete = false`
  // FIXME: ensure `exchange` has `expires` ... or compute it from `ttl`

  // insert the exchange and get the updated record
  const now = Date.now();
  const meta = {created: now, updated: now};
  const {localId: localExchangerId} = parseLocalId({id: localExchangerId});
  const record = {
    localExchangerId,
    meta,
    exchange
  };

  try {
    const collection = database.collections[COLLECTION_NAME];
    const result = await collection.insertOne(record);
    return result.ops[0];
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
  assert128BitId(id);

  const {localId: localExchangerId} = parseLocalId({id: exchangerId});
  const collection = database.collections[COLLECTION_NAME];
  const query = {localExchangerId, 'exchange.id': id};
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
  assert128BitId(id);

  // build update
  const now = Date.now();
  const update = {};
  update.$set = {'exchange.complete': true, 'meta.updated': now};
  // FIXME: also compute and set new `expires` based on exchange 'completedTtl`
  // (bikeshed name)

  const {localId: localExchangerId} = parseLocalId({id: exchangerId});

  const collection = database.collections[COLLECTION_NAME];
  const query = {
    localExchangerId,
    'exchange.id': id,
    'exchange.complete': false
  };

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await collection.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  let result;
  try {
    result = await collection.updateOne(query, update);
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

  if(result.result.n > 0) {
    // document upserted or modified: success
    return true;
  }

  // if no document was matched, try to get an existing exchange; if the
  // exchange does not exist, a not found error will be automatically thrown
  const record = await get({exchangerId: exchangerId, id});

  // the exchange DOES exist, but was already completed, which is an error
  // condition that must result in an auto-revocation of VCs or a
  // notification (TBD by the information stored in the returned exchange
  // record)
  // FIXME: handle auto-revocation / notification
}

/**
 * An object containing information on the query plan.
 *
 * @typedef {object} ExplainObject
 */
