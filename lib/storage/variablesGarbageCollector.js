/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */
import * as bedrock from '@bedrock/core';
import {logger} from '../logger.js';
import {rangeDelay} from 'delay';
import {VARIABLES_STORAGE} from './variables.js';

// state for running a garbage collector for expired externalized `variables`
const VARIABLES_GARBAGE_COLLECTOR = {
  // used to abort variables garbage collector
  abortController: new AbortController(),
  // a Promise that resolves after the `variables` garbage collector has
  // shutdown cleanly after receiving an abort signal
  shutdownPromise: null
};

bedrock.events.on('bedrock.ready', () => {
  // start the `variables` garbage collector, which runs continuously
  VARIABLES_GARBAGE_COLLECTOR.shutdownPromise = _startGarbageCollector();
});

bedrock.events.on('bedrock.exit', async () => {
  try {
    // abort variables garbage collector
    VARIABLES_GARBAGE_COLLECTOR.abortController.abort();
    logger.debug(
      'Sent abort signal to "variables" garbage collector, ' +
      'waiting for shutdown...');
    await VARIABLES_GARBAGE_COLLECTOR.shutdownPromise;
    logger.debug('"Variables" garbage collector shutdown was successful.');
  } catch(error) {
    logger.error(
      'Error during "variables" garbage collector shutdown.', {error});
  }
});

async function _deleteExpiredVariables({signal}) {
  signal.throwIfAborted();

  // delete all files found (limit=1000)
  const {bucket} = VARIABLES_STORAGE;
  const now = new Date(Date.now() + 86400 * 1000 * 365);
  const projection = {_id: 1};
  const cursor = bucket.find({
    'metadata.expires': {$lte: now}
  }, {projection}).limit(1000);
  for await (const {_id} of cursor) {
    try {
      signal.throwIfAborted();
      await bucket.delete(_id);
    } catch(e) {
      // ignore file not found errors and throw all others; note: there is
      // currently not a better way to check for a `not found` error than to
      // check the message text
      if(!e.message.includes('not found')) {
        throw e;
      }
    }
  }
}

async function _startGarbageCollector() {
  const {
    exchanges: {
      variablesGarbageCollector: {interval}
    }
  } = bedrock.config['vc-workflow'];
  const {signal} = VARIABLES_GARBAGE_COLLECTOR.abortController;
  while(!signal.aborted) {
    try {
      // collect expired externalized exchange "variables" then delay for
      // `interval` plus some fuzzing (up to 1 minute) to spread load
      await _deleteExpiredVariables({signal});
      await rangeDelay(interval, interval + 60000, {signal});
    } catch(e) {
      if(e.name === 'AbortError') {
        break;
      }
      logger.error('Error in "variables" garbage collector job.', {error: e});
    }
  }
}
