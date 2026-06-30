/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import {decodeVariables, encodeVariables} from './variables.js';
import {
  EXCHANGE_EXPIRY_GRACE_PERIOD, EXCHANGE_TTL_DEFAULT
} from '../constants.js';
import {parseLocalId, stripStacktrace} from '../helpers.js';
import assert from 'assert-plus';
import {logger} from '../logger.js';
import {serializeError} from 'serialize-error';

// ensure externalized `variables` garbage collector runs
import './variablesGarbageCollector.js';

const {util: {BedrockError}} = bedrock;

/* Note: Exchanges have default TTLs of 15 minutes and are always in one of
four states: `pending`, `active`, `complete`, or `invalid`. They can only
transition from `pending` to `complete` or from `complete` to `invalid`.

If an exchange is marked as complete, any attempt to mark it complete again
will result in an action, as specified in the exchange record, being taken
such as auto-revocation or notification.

Each pending exchange is an instance of a workflow. A workflow may have
one or more steps, each that might issue, verify, or deliver VCs. Capabilities
must be provided to issue or verify VCs. */

const COLLECTION_NAME = 'vc-exchange';
const BUCKET_NAME = 'vc-exchange-variables';

// allow updates to the last error every 500ms
const LAST_ERROR_UPDATE_CONSTRAINTS = {
  // if the exchange has been updated 5 or more times, apply the time limit
  sequenceThreshold: 5,
  // 1 second must expire before updating last error once sequence threshold
  // has been hit
  updateTimeLimit: 1000
};

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections([
    COLLECTION_NAME, `${BUCKET_NAME}.files`
  ]);

  await database.createIndexes([{
    // cover exchange queries by local workflow ID + exchange ID
    collection: COLLECTION_NAME,
    fields: {localWorkflowId: 1, 'exchange.id': 1},
    options: {
      partialFilterExpression: {
        localWorkflowId: {$exists: true}
      },
      unique: true
    }
  }, {
    // backwards compatibility: cover exchange queries by
    // local exchanger ID + exchange ID; local exchanger ID is the same as
    // local workflow ID and this index can be eventually dropped once no
    // deployments use `localExchangerId`
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
 * @param {string} options.workflowId - The ID of the workflow that the
 *   exchange is associated with.
 * @param {object} options.exchange - The exchange to insert.
 *
 * @returns {Promise<object>} Resolves to the database record.
 */
export async function insert({workflowId, exchange}) {
  assert.string(workflowId, 'workflowId');
  assert.object(exchange, 'exchange');
  assert.string(exchange.id, 'exchange.id');
  assert.string(exchange.expires, 'exchange.expires');
  // optional time to live in seconds
  assert.optionalNumber(exchange.ttl, 'exchange.ttl');
  // optional variables to use in VC templates
  assert.optionalObject(exchange.variables, 'exchange.variables');
  // optional current step in the exchange
  assert.optionalString(exchange.step, 'exchange.step');
  // optional protocols in exchange
  assert.optionalObject(exchange.protocols, 'exchange.protocols');

  // build exchange record
  const now = Date.now();
  const meta = {
    created: now,
    updated: now,
    expires: new Date(exchange.expires)
  };
  // possible states are: `pending`, `active`, `complete`, or `invalid`
  exchange = {...exchange, sequence: 0, state: 'pending'};
  const {localId: localWorkflowId} = parseLocalId({id: workflowId});
  const record = {
    localWorkflowId,
    // backwards compatibility: enable existing systems to find record
    localExchangerId: localWorkflowId,
    meta,
    exchange: await encodeVariables({workflowId, exchange, meta})
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
 * @param {string} options.workflowId - The ID of the workflow that the
 *   exchange is associated with.
 * @param {string} options.id - The ID of the exchange to retrieve.
 * @param {boolean} [options.allowExpired=false] - Controls whether an expired
 *   exchange that is still in the database can be retrieved or not.
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<object | ExplainObject>} Resolves with the record that
 *   matches the query or an ExplainObject if `explain=true`.
 */
export async function get({
  workflowId, id, allowExpired = false, explain = false
} = {}) {
  assert.string(workflowId, 'workflowId');
  assert.string(id, 'id');

  const {base, localId: localWorkflowId} = parseLocalId({id: workflowId});
  const collection = database.collections[COLLECTION_NAME];
  const query = {
    localWorkflowId,
    'exchange.id': id,
    // treat exchange as not found if invalid
    'exchange.state': {$ne: 'invalid'}
  };
  // backwards compatibility: query on `localExchangerId`
  if(base.endsWith('/exchangers')) {
    query.localWorkflowId = {$in: [null, localWorkflowId]};
    query.localExchangerId = localWorkflowId;
  }
  const projection = {_id: 0, exchange: 1, meta: 1};

  if(explain) {
    // 'find().limit(1)' is used here because 'findOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await collection.find(query, {projection}).limit(1);
    return cursor.explain('executionStats');
  }

  let record = await collection.findOne(query, {projection});
  if(record && !allowExpired) {
    // ensure `expires` is enforced programmatically even if background job
    // has not yet removed the record; force unexpiring exchanges to be not
    // found via this code path -- any exchanges without an expiration date
    // are from very old software and they will need to be manually cleaned up
    // in the database
    const now = new Date();
    // note: for undefined `expires`, this will be `NaN || now` => `now`
    const expires = new Date(Date.parse(record.exchange.expires) || now);
    if(now >= expires) {
      record = null;
    }
  }
  if(!record) {
    throw new BedrockError('Exchange not found.', {
      name: 'NotFoundError',
      details: {
        workflow: workflowId,
        // backwards compatibility
        exchanger: workflowId,
        exchange: id,
        httpStatusCode: 404,
        public: true
      }
    });
  }

  record.exchange = await decodeVariables({workflowId, record});

  // backwards compatibility; initialize `sequence`
  if(record.exchange.sequence === undefined) {
    const query = {
      localWorkflowId,
      'exchange.id': id,
      'exchange.sequence': null
    };
    // backwards compatibility: query on `localExchangerId`
    if(base.endsWith('/exchangers')) {
      query.localWorkflowId = {$in: [null, localWorkflowId]};
      query.localExchangerId = localWorkflowId;
    }

    await collection.updateOne(query, {$set: {'exchange.sequence': 0}});
    record.exchange.sequence = 0;
  }

  return record;
}

/**
 * Updates a pending or active exchange with new state, variables, step, and
 * TTL, and error information.
 *
 * @param {object} options - The options to use.
 * @param {string} options.workflowId - The ID of the workflow the exchange
 *   is associated with.
 * @param {object} options.exchange - The exchange to update.
 * @param {object} options.meta - The exchange meta to update.
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<boolean | ExplainObject>} Resolves with `true` on update
 *   success or an ExplainObject if `explain=true`.
 */
export async function update({
  workflowId, exchange, meta, explain = false
} = {}) {
  assert.string(workflowId, 'workflowId');
  assert.object(exchange, 'exchange');
  const {id} = exchange;

  // force exchange to expire if this code has been called on an old exchange
  // with no expiration date
  let updateExpires = false;
  if(exchange.expires === undefined) {
    updateExpires = true;
    const ttl = exchange.ttl ?? EXCHANGE_TTL_DEFAULT;
    // TTL is in seconds, convert to milliseconds
    const expires = new Date(Date.now() + ttl * 1000);
    exchange.expires = expires.toISOString().replace(/\.\d+Z$/, 'Z');
  }

  // encode variable content for storage in mongoDB
  meta = {...meta};
  exchange = await encodeVariables({workflowId, exchange, meta});

  // build update
  const update = _buildUpdate({exchange, meta, updateExpires});

  const {base, localId: localWorkflowId} = parseLocalId({id: workflowId});

  const collection = database.collections[COLLECTION_NAME];
  const query = {
    localWorkflowId,
    'exchange.id': id,
    // exchange sequence must match previous sequence
    'exchange.sequence': exchange.sequence - 1,
    // previous state must be `pending` or `active` in order to update it
    'exchange.state': {$in: ['pending', 'active']}
  };
  // backwards compatibility: query on `localExchangerId`
  if(base.endsWith('/exchangers')) {
    query.localWorkflowId = {$in: [null, localWorkflowId]};
    query.localExchangerId = localWorkflowId;
  }

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
    throw new BedrockError('Could not update exchange.', {
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
  await get({workflowId, id});

  /* Note: Here the exchange *does* exist, but the step or state did not
  match which is a conflict error. */

  // throw duplicate completed exchange error
  throw new BedrockError('Could not update exchange; conflict error.', {
    name: 'InvalidStateError',
    details: {
      public: true,
      // this is a client-side conflict error
      httpStatusCode: 409
    }
  });
}

/**
 * Marks an exchange as complete.
 *
 * @param {object} options - The options to use.
 * @param {string} options.workflowId - The ID of the workflow the exchange
 *   is associated with.
 * @param {object} options.exchange - The exchange to mark as complete.
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<boolean | ExplainObject>} Resolves with `true` on update
 *   success or an ExplainObject if `explain=true`.
 */
export async function complete({workflowId, exchange, explain = false} = {}) {
  assert.string(workflowId, 'workflowId');
  assert.object(exchange, 'exchange');
  if(exchange.state !== 'complete') {
    throw new Error('"exchange.state" must be set to "complete".');
  }
  const {id} = exchange;

  // build update
  const update = _buildUpdate({exchange});

  const {base, localId: localWorkflowId} = parseLocalId({id: workflowId});

  const collection = database.collections[COLLECTION_NAME];
  const query = {
    localWorkflowId,
    'exchange.id': id,
    // exchange sequence must match previous sequence
    'exchange.sequence': exchange.sequence - 1,
    // previous state must be `pending` or `active` in order to change to
    // `complete`
    'exchange.state': {$in: ['pending', 'active']}
  };
  // backwards compatibility: query on `localExchangerId`
  if(base.endsWith('/exchangers')) {
    query.localWorkflowId = {$in: [null, localWorkflowId]};
    query.localExchangerId = localWorkflowId;
  }

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
  const record = await get({workflowId, id});

  /* Note: Here the exchange *does* exist, but couldn't be updated because
  another process changed it. That change either left it in a still pending
  state or it was already completed. If it was already completed, it is an
  error condition that must result in invalidating the exchange. */
  if(record.exchange.state === 'pending' ||
    record.exchange.state === 'active') {
    // exchange still pending, another process updated it
    throw new BedrockError('Could not update exchange; conflict error.', {
      name: 'InvalidStateError',
      details: {
        public: true,
        // this is a client-side conflict error
        httpStatusCode: 409
      }
    });
  }

  // state is either `complete` or `invalid`, so throw duplicate completed
  // exchange error and invalidate exchange if needed, but do not throw any
  // error to client; only log it
  if(record.exchange.state !== 'invalid') {
    _invalidateExchange({record}).catch(
      error => logger.error(`Could not invalidate exchange "${id}".`, {error}));
  }

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

/**
 * Sets the last error associated with an exchange, provided that the exchange
 * has not been recently or frequently updated.
 *
 * @param {object} options - The options to use.
 * @param {string} options.workflowId - The ID of the workflow the exchange
 *   is associated with.
 * @param {object} options.exchange - The exchange to update with `lastError`
 *   set.
 * @param {object} options.lastUpdated - The last update time (in milliseconds).
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<boolean | ExplainObject>} Resolves with `true` on update
 *   success or an ExplainObject if `explain=true`.
 */
export async function setLastError({
  workflowId, exchange, lastUpdated, explain = false
} = {}) {
  assert.string(workflowId, 'workflowId');
  assert.object(exchange, 'exchange');
  assert.object(exchange.lastError, 'exchange.lastError');
  assert.number(lastUpdated, 'lastUpdate');

  // prevent too many updates to an exchange to write the last error to it
  // by limiting to a few
  const now = Date.now();
  if(exchange.sequence > LAST_ERROR_UPDATE_CONSTRAINTS.sequenceThreshold &&
    now < (lastUpdated + LAST_ERROR_UPDATE_CONSTRAINTS.updateTimeLimit)) {
    // deny update, too many last error updates
    return false;
  }

  // build update
  const update = {
    $inc: {'exchange.sequence': 1},
    $set: {
      'meta.updated': now,
      'exchange.lastError': serializeError(stripStacktrace(exchange.lastError))
    }
  };

  const {base, localId: localWorkflowId} = parseLocalId({id: workflowId});

  const {id} = exchange;
  const collection = database.collections[COLLECTION_NAME];
  const query = {
    localWorkflowId,
    'exchange.id': id,
    // exchange sequence must match previous sequence
    'exchange.sequence': exchange.sequence - 1
  };
  // backwards compatibility: query on `localExchangerId`
  if(base.endsWith('/exchangers')) {
    query.localWorkflowId = {$in: [null, localWorkflowId]};
    query.localExchangerId = localWorkflowId;
  }

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
    throw new BedrockError('Could not update exchange.', {
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
  await get({workflowId, id});

  /* Note: Here the exchange *does* exist, but the step or state did not
  match which is a conflict error. */

  // throw duplicate completed exchange error
  throw new BedrockError('Could not update exchange; conflict error.', {
    name: 'InvalidStateError',
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

  /* Consider perform auto-revocation of the VCs or notification (the action to
  take is specified in the exchange record). */
  // FIXME: handle auto-revocation / notification in background; do not throw
  // errors to client; consider removing invalidation state as well and rely
  // solely on TTL to manage exchange secrecy/abuse
}

async function _markExchangeInvalid({record}) {
  const now = Date.now();

  // mark exchange invalid
  try {
    const query = {
      localWorkflowId: record.localWorkflowId,
      'exchange.id': record.exchange.id
    };
    // backwards compatibility: query on `localExchangerId`
    if(!record.localWorkflowId) {
      query.localExchangerId = record.localExchangerId;
    }
    const update = {
      $set: {
        'exchange.state': 'invalid',
        'meta.updated': now,
        'meta.expires': new Date(now + EXCHANGE_EXPIRY_GRACE_PERIOD)
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

function _buildUpdate({exchange, meta, updateExpires = false}) {
  // build update
  const now = Date.now();
  const update = {
    $inc: {'exchange.sequence': 1},
    $set: {
      'exchange.referenceId': exchange.referenceId ?? exchange.id,
      'exchange.state': exchange.state,
      'exchange.secrets': exchange.secrets,
      'exchange.variables': exchange.variables,
      'meta.updated': now
    },
    $unset: {}
  };
  if(exchange.step !== undefined) {
    update.$set['exchange.step'] = exchange.step;
  }
  // only update (fix) `expires` if it was not previously set (a very old
  // exchange is being updated)
  if(updateExpires) {
    // TTL is in seconds, convert to milliseconds
    const expires = new Date(exchange.expires);
    // unset any previously set `ttl` and set `expires` instead
    update.$unset['exchange.ttl'] = true;
    update.$set['meta.expires'] = expires;
    update.$set['exchange.expires'] = exchange.expires;
  }
  if(exchange.lastError !== undefined) {
    update.$set['exchange.lastError'] =
      serializeError(stripStacktrace(exchange.lastError));
  } else {
    update.$unset['exchange.lastError'] = true;
  }
  if(meta?.variablesFilename === false) {
    update.$unset['meta.variablesFilename'] = true;
  } else if(typeof meta?.variablesFilename === 'string') {
    update.$set['meta.variablesFilename'] = meta.variablesFilename;
  }

  return update;
}

/**
 * An object containing information on the query plan.
 *
 * @typedef {object} ExplainObject
 */
