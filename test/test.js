/*!
 * Copyright (c) 2016-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {getServiceIdentities} from '@bedrock/app-identity';
import {handlers} from '@bedrock/meter-http';
import {jsonLdDocumentLoader} from '@bedrock/jsonld-document-loader';
import '@bedrock/ssm-mongodb';
import '@bedrock/kms';
import '@bedrock/https-agent';
import '@bedrock/meter';
import '@bedrock/meter-usage-reporter';
import '@bedrock/server';
import '@bedrock/kms-http';
import '@bedrock/edv-storage';
import '@bedrock/vc-issuer';
import '@bedrock/vc-verifier';

import {mockData} from './mocha/mock.data.js';

// used for VCB tests
const contexts = new Map([
  ['https://www.w3.org/ns/credentials/examples/v2', {
    '@context': {
      '@vocab': 'https://www.w3.org/ns/credentials/examples#'
    }
  }],
  // VCB spec test vector
  ['https://w3id.org/utopia/v2', {
    /* eslint-disable */
    "@context": {
      "@protected": true,
      "id": "@id",
      "type": "@type",
      "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj": "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj",
      "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj#zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj": "did:key:zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj#zDnaeZSD9XcuULaS8qmgDUa6TMg2QjF9xABnZK42awDH3BEzj",
      "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj": "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj",
      "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj#zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj": "did:key:zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj#zDnaeWjKfs1ob9QcgasjYSPEMkwq31hmvSAWPVAgnrt1e9GKj",
      "https://sandbox.platform.veres.dev/statuses/z19rJ4oGrbFCqf3cNTVDHSbNd/status-lists": "https://sandbox.platform.veres.dev/statuses/z19rJ4oGrbFCqf3cNTVDHSbNd/status-lists"
    }
    /* eslint-enable */
  }],
  ['https://www.w3.org/2018/credentials/examples/v1',
    mockData.examplesContext
  ]
]);
jsonLdDocumentLoader.addDocuments({documents: contexts});

bedrock.events.on('bedrock.init', async () => {
  /* Handlers need to be added before `bedrock.start` is called. These are
  no-op handlers to enable meter usage without restriction */
  handlers.setCreateHandler({
    handler({meter} = {}) {
      // use configured meter usage reporter as service ID for tests
      const clientName = mockData.productIdMap.get(meter.product.id);
      const serviceIdentites = getServiceIdentities();
      const serviceIdentity = serviceIdentites.get(clientName);
      if(!serviceIdentity) {
        throw new Error(`Could not find identity "${clientName}".`);
      }
      meter.serviceId = serviceIdentity.id;
      return {meter};
    }
  });
  handlers.setUpdateHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setRemoveHandler({handler: ({meter} = {}) => ({meter})});
  handlers.setUseHandler({handler: ({meter} = {}) => ({meter})});
});

// mock oauth2 authz server routes; these are for creating workflows, not
// for performing OID4VCI delivery
bedrock.events.on('bedrock-express.configure.routes', async app => {
  app.get(mockData.oauth2IssuerConfigRoute, (req, res) => {
    res.json(mockData.oauth2Config);
  });
  app.get('/oauth2/jwks', (req, res) => {
    res.json(mockData.jwks);
  });
});

import '@bedrock/test';
bedrock.start();
