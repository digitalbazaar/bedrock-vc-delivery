/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {getZcapClient} from './helpers.js';

export async function createChallenge({exchanger} = {}) {
  // create zcap client for creating challenges
  const {zcapClient, zcaps} = await getZcapClient({exchanger});

  // create challenge
  const capability = zcaps.verify;
  const {data: {challenge}} = await zcapClient.write({
    url: `${capability.invocationTarget}/challenges`,
    capability,
    json: {}
  });
  return {challenge};
}

export async function verify({exchanger, presentation} = {}) {
  // create zcap client for verifying
  const {zcapClient, zcaps} = await getZcapClient({exchanger});

  // verify presentation
  const capability = zcaps.verify;
  const result = await zcapClient.write({
    url: `${capability.invocationTarget}/presentations/verify`,
    capability,
    json: {
      options: {
        challenge,
        checks: ['proof'],
      },
      verifiablePresentation: presentation
    }
  });

  const {data: {verified, challengeUses}} = result;
  return {verified, challengeUses};
}

export async function verifyDidProofJwt({exchanger, exchange, jwt} = {}) {
  // FIXME: implement
}
