/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import '@bedrock/app-identity';
import '@bedrock/did-io';
import '@bedrock/https-agent';
import '@bedrock/mongodb';
import '@bedrock/service-agent';
import '@bedrock/vc-delivery';
import '@bedrock/vc-issuer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

config.mocha.options.fullTrace = true;
config.mocha.tests.push(path.join(__dirname, 'mocha'));
config.mocha.tests.push(
  path.join(__dirname, 'mocha', 'backwards-compatibility'));

// MongoDB
config.mongodb.name = 'bedrock_vc_delivery_test';
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];
// drop all collections on initialization
config.mongodb.dropCollections = {};
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;

// create test application identities
config['app-identity'].seeds.services['vc-exchanger'] = {
  id: 'did:key:z6Mkw4VNHJ2JHnepRHsRkGfJhxLh6penJmp7wnozgspgn7hR',
  seedMultibase: 'z1AkfV2wAxeDTyMTBe7Sh2Qvn7wKoy34dHTQGhFbVD52NmA',
  serviceType: 'vc-exchanger'
};
config['app-identity'].seeds.services['vc-issuer'] = {
  id: 'did:key:z6MkiZ433VBt3jx19vBeHwshV37imwfA4FVYbN7nyEcccRg1',
  seedMultibase: 'z1AdSyTUt63FBfJNbNGW4WQxvyWeEuKC3wXfU9zPAXgoCu4',
  serviceType: 'vc-issuer'
};
config['app-identity'].seeds.services['vc-verifier'] = {
  id: 'did:key:z6Mkqaem14MRKwArmCMHXdbZYyfjMXpot4qKZn2WBvQLn4yp',
  seedMultibase: 'z1AdtQzyvR1xuEKpxgrrNWhWag7WjEEqSzUpJNuPPkyBpm7',
  serviceType: 'vc-verifier'
};

// use local KMS for testing
config['service-agent'].kms.baseUrl = 'https://localhost:18443/kms';

// disable veres one fetching
config['did-io'].methodOverrides.v1.disableFetch = true;
