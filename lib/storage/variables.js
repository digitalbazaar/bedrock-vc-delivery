/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import {createHash} from 'node:crypto';
import {EXCHANGE_EXPIRY_GRACE_PERIOD} from '../constants.js';
import {PassThrough} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {buffer as readIntoBuffer} from 'node:stream/consumers';

const {util: {BedrockError}} = bedrock;

/* Note: If the total size for `exchange.variables` is less than
`VARIABLES_SIZE_LIMIT` then the variables are stored in the exchange record.
Otherwise, the variables must be converted to JSON and externally stored, in
a gridfs bucket. Additionally, if the variables contain any JSON keys that
contain an invalid MongoDB key character, the variables must be stored as
JSON either within the exchange document or externally (where the JSON is
stored is determined by size limit mentioned above).

Importantly, all deployed workflow systems must be upgraded to enable reading
externalized variables prior to writing any externalized variables. So the
size limit must be at least 10MiB as old software prohibited submitting any
payloads larger than this over HTTP. That 10MiB HTTP limit must not be raised
until all systems have been upgraded to enable reading externalized variables,
ensuring no externalized variables will be written before then.

There still needs to be a cap on the maximum payload that will be accepted
on various HTTP endpoints to prevent DoS, but once systems support externally
stored variables, the limit can be raised beyond 10MiB. Additionally, a feature
to enable different limits per workflow could be implemented if desired (but it
will require different HTTP body parser setup). */

// very generous 1 hour grace period before externalized variables are deleted
// after an exchange expires to allow for various asynchronous behaviors
const VARIABLES_EXPIRY_GRACE_PERIOD = 1000 * 60 * 60;

// for gridfs storage of large exchange `variables`
export const VARIABLES_STORAGE = {
  name: 'vc-exchange-variables',
  bucket: null
};

// limit to exchange `variables` size; at this size or larger, `variables`
// must be externalized and stored in a gridfs bucket
const VARIABLES_SIZE_LIMIT = 1024 * 1024 * 10;

// used to determine whether `variables` can be stored parsed as BSON or must
// be converted to JSON
const MONGODB_ILLEGAL_KEY_CHAR_REGEX = /[%$.]/;

bedrock.events.on('bedrock-mongodb.ready', async () => {
  await database.openCollections([`${VARIABLES_STORAGE.name}.files`]);

  VARIABLES_STORAGE.bucket = database.createGridFSBucket({
    bucketName: VARIABLES_STORAGE.name
  });

  await database.createIndexes([{
    // enables content-based ID lookups in `VARIABLES_STORAGE.name` bucket
    collection: `${VARIABLES_STORAGE.name}.files`,
    fields: {filename: 1},
    options: {
      unique: true
    }
  }, {
    // enables an application worker (defined below) to find and delete expired
    // `files` in the `VARIABLES_STORAGE.name` bucket; a TTL index is not used
    // because `chunks` must also be removed and chunks do not contain a
    // similar metadata field that would allow for robust atomic updates and
    // clean up; so the GridFS file deletion API is used in the application
    // worker
    collection: `${VARIABLES_STORAGE.name}.files`,
    // `metadata` is a built-in property for the `files` document schema; and
    // `expires` will be added to it
    fields: {'metadata.expires': 1},
    options: {
      partialFilterExpression: {
        'metadata.expires': {$exists: true}
      },
      unique: false
    }
  }]);
});

export async function encodeVariables({workflowId, exchange, meta}) {
  // express variables as JSON to determine total size; a future optimization
  // might be able to avoid converting to JSON (in some cases)
  const {variables, ...rest} = exchange;
  const variablesJson = JSON.stringify(variables);

  // any `variables` that are under the size limit can be stored in the
  // exchange document itself
  // FIXME: always execute this conditional -- until a major release is made
  // (or a determination that a safe minor release is possible), ensuring that
  // externalized `variables` storage is not used yet
  if(true || variablesJson.length < VARIABLES_SIZE_LIMIT) {
    meta.variablesFilename = false;
    // if any object has a key that uses a character that is not legal in
    // a JSON key in mongoDB document, then stringify all the variables
    return !_hasIllegalMongoDBKeyChar(variables) ?
      exchange : {...rest, variables: variablesJson};
  }

  // generate content-based identifier for filename; noting that an local
  // exchange ID MUST NOT (and currently does not) include a `_` character as
  // it is used as a delimiter here
  const buffer = Buffer.from(variablesJson, 'utf8');
  const filename = `${exchange.id}_${_multibaseMultihashSha256(buffer)}`;
  meta.variablesFilename = filename;

  // create gridfs file metadata w/expiry; `exchange.expires` MUST be set
  const expires = new Date(exchange.expires);
  const metadata = {
    // add exchange grace period to expiry to cover maximum exchange TTL and
    // add a generous `variables` grace period as well
    expires: new Date(
      expires.getTime() +
      EXCHANGE_EXPIRY_GRACE_PERIOD + VARIABLES_EXPIRY_GRACE_PERIOD)
  };

  // store variables; any duplicate content-based identifier will throw a
  // duplicate error which can be safely ignored
  const stream = new PassThrough();
  stream.end(buffer);
  try {
    await pipeline(
      stream,
      VARIABLES_STORAGE.bucket.openUploadStream(filename, {metadata}));
  } catch(e) {
    if(!database.isDuplicateError(e)) {
      throw new BedrockError(`Could not store exchange variables.`, {
        name: 'OperationError',
        details: {
          workflow: workflowId,
          exchange: exchange.id,
          public: true,
          httpStatusCode: 500
        },
        cause: e
      });
    }
  }

  return {...rest};
}

export async function decodeVariables({workflowId, record}) {
  const {exchange, meta} = record;

  // if `variables` are stored as a string, parse them from JSON
  if(typeof exchange.variables === 'string') {
    return {...exchange, variables: JSON.parse(exchange.variables)};
  }

  // if `meta` indicates that the variables are externalized, then read them
  // from the gridfs variables bucket
  if(meta.variablesFilename) {
    try {
      const {bucket} = VARIABLES_STORAGE;
      const buffer = await readIntoBuffer(
        bucket.openDownloadStreamByName(meta.variablesFilename));
      exchange.variables = JSON.parse(buffer.toString('utf8'));
    } catch(e) {
      throw new BedrockError(`Could not load exchange variables.`, {
        name: 'OperationError',
        details: {
          workflow: workflowId,
          exchange: exchange.id,
          public: true,
          httpStatusCode: 500
        },
        cause: e
      });
    }
  }

  return exchange;
}

function _hasIllegalMongoDBKeyChar(value) {
  if(Array.isArray(value)) {
    for(const e of value) {
      if(_hasIllegalMongoDBKeyChar(e)) {
        return true;
      }
    }
  } else if(value && typeof value === 'object') {
    const keys = Object.keys(value);
    for(const key of keys) {
      if(MONGODB_ILLEGAL_KEY_CHAR_REGEX.test(key) ||
        _hasIllegalMongoDBKeyChar(value[key])) {
        return true;
      }
    }
  }
  return false;
}

function _multibaseMultihashSha256(buffer) {
  // compute SHA-256 hash
  const digest = createHash('sha256').update(buffer).digest();

  // format as multihash digest
  // sha2-256: 0x12, length: 32 (0x20), digest value
  const mh = new Uint8Array(34);
  mh[0] = 0x12;
  mh[1] = 0x20;
  mh.set(digest, 2);

  // return as multibase-base64url-encoded value
  return 'u' + Buffer.from(mh).toString('base64url');
}
