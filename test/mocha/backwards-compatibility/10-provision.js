/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import {CapabilityAgent} from '@digitalbazaar/webkms-client';
import {httpClient} from '@digitalbazaar/http-client';
import {mockData} from './mock.data.js';

describe('exchanger backwards-compatibility: ' +
  'provision', () => {
  let capabilityAgent;
  let exchangerIssueZcap;
  let exchangerCredentialStatusZcap;
  let exchangerVerifyPresentationZcap;
  beforeEach(async () => {
    ({
      exchangerIssueZcap, exchangerVerifyPresentationZcap, capabilityAgent
    } = await helpers.provisionDependencies());
  });

  describe('create config', () => {
    it('throws error on bad zcaps', async () => {
      let err;
      let result;
      try {
        result = await helpers.createExchangerConfig({
          capabilityAgent, zcaps: {invalid: ''}
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.details.errors.should.have.length(1);
      const [error] = err.data.details.errors;
      error.name.should.equal('ValidationError');
      error.message.should.contain('should be object');
    });
    it('creates a config with no zcaps', async () => {
      let err;
      let result;
      try {
        result = await helpers.createExchangerConfig({capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'sequence', 'meterId'
      ]);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
    });
    it('creates a config with a client-chosen ID', async () => {
      let err;
      let result;
      try {
        const localId = await helpers.generateRandom();
        result = await helpers.createExchangerConfig({
          capabilityAgent, configOptions: {
            id: `${mockData.baseUrl}/exchangers/${localId}`
          }
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'sequence', 'meterId'
      ]);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
    });
    it('creates a config with only an issue zcap', async () => {
      let err;
      let result;
      try {
        const zcaps = {
          issue: exchangerIssueZcap
        };
        result = await helpers.createExchangerConfig({capabilityAgent, zcaps});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'sequence', 'meterId', 'zcaps'
      ]);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
    });
    it('creates a config with issue, status, and verify zcaps', async () => {
      let err;
      let result;
      try {
        const zcaps = {
          issue: exchangerIssueZcap,
          credentialStatus: exchangerCredentialStatusZcap,
          verifyPresentation: exchangerVerifyPresentationZcap
        };
        result = await helpers.createExchangerConfig({capabilityAgent, zcaps});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'sequence', 'meterId', 'zcaps'
      ]);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
    });
    it('creates a config with credential templates', async () => {
      let err;
      let result;
      try {
        const zcaps = {
          issue: exchangerIssueZcap,
          credentialStatus: exchangerCredentialStatusZcap,
          verifyPresentation: exchangerVerifyPresentationZcap
        };
        const credentialTemplates = [{
          type: 'jsonata',
          template: '{}'
        }];
        result = await helpers.createExchangerConfig(
          {capabilityAgent, zcaps, credentialTemplates});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'sequence', 'meterId', 'zcaps',
        'credentialTemplates'
      ]);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
    });
    it('throws with credential templates and no issue zcap', async () => {
      let err;
      let result;
      try {
        const credentialTemplates = [{
          type: 'jsonata',
          template: '{}'
        }];
        result = await helpers.createExchangerConfig({
          capabilityAgent, credentialTemplates
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      should.exist(err.data);
      err.data.name.should.equal('DataError');
      const {message} = err.data.details.cause;
      message.should.contain(
        'A capability to issue credentials is required when credential ' +
        'templates are provided.');
    });
    it('throws if duplicate client-chosen ID is used', async () => {
      let err;
      let result;
      try {
        // create config (should pass)
        result = await helpers.createExchangerConfig({
          capabilityAgent, configOptions: {
            id: `${mockData.baseUrl}/exchangers/z1A183gxYRXYFUnHUXsS7KVmA`
          }
        });
        should.exist(result);
        // try to create duplicate (should throw)
        result = undefined;
        result = await helpers.createExchangerConfig({
          capabilityAgent, configOptions: {
            id: `${mockData.baseUrl}/exchangers/z1A183gxYRXYFUnHUXsS7KVmA`
          }
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      should.exist(err.data);
      err.status.should.equal(409);
      err.data.name.should.equal('DuplicateError');
      err.data.message.should.contain('Duplicate configuration');
    });
    it('throws if invalid client-chosen ID is used', async () => {
      let err;
      let result;
      try {
        result = await helpers.createExchangerConfig({
          capabilityAgent, configOptions: {
            id: `${mockData.baseUrl}/exchangers/foo`
          }
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      should.exist(err.data);
      err.status.should.equal(400);
      err.data.name.should.equal('DataError');
      err.data.message.should.contain('Configuration validation failed');
      err.data.details.cause.message.should.contain(
        'Invalid client-provided configuration ID');
    });
    it('creates a config including proper ipAllowList', async () => {
      const ipAllowList = ['127.0.0.1/32', '::1/128'];

      let err;
      let result;
      try {
        result = await helpers.createExchangerConfig(
          {capabilityAgent, ipAllowList});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'ipAllowList', 'sequence', 'meterId'
      ]);
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.controller.should.equal(capabilityAgentId);
      result.ipAllowList.should.eql(ipAllowList);
    });
    it('throws error on invalid ipAllowList', async () => {
      // this is not a valid CIDR
      const ipAllowList = ['127.0.0.1/33'];

      let err;
      let result;
      try {
        result = await helpers.createExchangerConfig(
          {capabilityAgent, ipAllowList});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.details.errors.should.have.length(1);
      const [error] = err.data.details.errors;
      error.name.should.equal('ValidationError');
      error.message.should.contain('should match pattern');
      error.details.path.should.equal('.ipAllowList[0]');
    });
    it('throws error on invalid ipAllowList', async () => {
      // an empty allow list is invalid
      const ipAllowList = [];

      let err;
      let result;
      try {
        result = await helpers.createExchangerConfig(
          {capabilityAgent, ipAllowList});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.details.errors.should.have.length(1);
      const [error] = err.data.details.errors;
      error.name.should.equal('ValidationError');
      error.message.should.contain('should NOT have fewer than 1 items');
      error.details.path.should.equal('.ipAllowList');
    });
    it('throws error on no "sequence"', async () => {
      const url = `${bedrock.config.server.baseUri}/exchangers`;
      const config = {
        controller: capabilityAgent.id
      };

      let err;
      let result;
      try {
        result = await httpClient.post(url, {agent, json: config});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.type.should.equal('ValidationError');
      err.data.message.should.equal(
        'A validation error occurred in the \'createConfigBody\' validator.');
    });
  });

  describe('get config', () => {
    it('gets a config', async () => {
      const zcaps = {
        issue: exchangerIssueZcap,
        verifyPresentation: exchangerVerifyPresentationZcap
      };
      const config = await helpers.createExchangerConfig(
        {capabilityAgent, zcaps});
      let err;
      let result;
      try {
        result = await helpers.getConfig({id: config.id, capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'sequence', 'meterId', 'zcaps'
      ]);
      result.id.should.equal(config.id);
    });
    it('gets a config w/oauth2', async () => {
      const zcaps = {
        issue: exchangerIssueZcap,
        verifyPresentation: exchangerVerifyPresentationZcap
      };
      const config = await helpers.createExchangerConfig(
        {capabilityAgent, zcaps, oauth2: true});
      const accessToken = await helpers.getOAuth2AccessToken(
        {configId: config.id, action: 'read', target: '/'});
      let err;
      let result;
      try {
        result = await helpers.getConfig({id: config.id, accessToken});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'authorization', 'controller', 'id', 'sequence', 'meterId', 'zcaps'
      ]);
      result.id.should.equal(config.id);
    });
    it('gets a config with ipAllowList', async () => {
      const ipAllowList = ['127.0.0.1/32', '::1/128'];

      const config = await helpers.createExchangerConfig(
        {capabilityAgent, ipAllowList});
      let err;
      let result;
      try {
        result = await helpers.getConfig({id: config.id, capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.keys([
        'controller', 'id', 'ipAllowList', 'sequence', 'meterId'
      ]);
      result.should.have.property('id');
      result.id.should.equal(config.id);
      result.ipAllowList.should.eql(ipAllowList);
    });
    it('returns NotAllowedError for invalid source IP', async () => {
      const ipAllowList = ['8.8.8.8/32'];

      const config = await helpers.createExchangerConfig(
        {capabilityAgent, ipAllowList});
      let err;
      let result;
      try {
        result = await helpers.getConfig({id: config.id, capabilityAgent});
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');
    });
  }); // get config

  describe('update config', () => {
    it('updates a config', async () => {
      // create new capability agent to change config `controller` to
      const capabilityAgent2 = await CapabilityAgent.fromSecret(
        {secret: 's2', handle: 'h2'});

      let err;
      let result;
      let existingConfig;
      try {
        existingConfig = result = await helpers.createExchangerConfig(
          {capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);

      // this update does not change the `meterId`
      const {id: url} = result;
      const newConfig = {
        ...existingConfig,
        controller: capabilityAgent2.id,
        sequence: 1
      };

      err = null;
      result = null;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result.data);
      result.status.should.equal(200);
      result.data.should.have.keys([
        'id', 'controller', 'sequence', 'meterId'
      ]);
      const expectedConfig = {
        ...existingConfig,
        ...newConfig
      };
      result.data.should.eql(expectedConfig);

      // should fail to retrieve the config now that controller
      // has changed
      err = null;
      result = null;
      try {
        result = await helpers.getConfig(
          {id: newConfig.id, capabilityAgent});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');

      // retrieve the config to confirm update was effective
      err = null;
      result = null;
      try {
        result = await helpers.getConfig(
          {id: newConfig.id, capabilityAgent: capabilityAgent2});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.eql(expectedConfig);
    });
    it('updates a config enabling oauth2', async () => {
      let err;
      let result;
      let existingConfig;
      try {
        existingConfig = result = await helpers.createExchangerConfig(
          {capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);

      // should fail to retrieve the config since `oauth2` is not yet
      // enabled
      const accessToken = await helpers.getOAuth2AccessToken(
        {configId: existingConfig.id, action: 'read', target: '/'});
      err = null;
      result = null;
      try {
        result = await helpers.getConfig(
          {id: existingConfig.id, accessToken});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');

      // this update adds `oauth2` authz config
      const {baseUri} = bedrock.config.server;
      let newConfig = {
        ...existingConfig,
        sequence: 1,
        authorization: {
          oauth2: {
            issuerConfigUrl: `${baseUri}${mockData.oauth2IssuerConfigRoute}`
          }
        }
      };
      err = null;
      result = null;
      try {
        const url = existingConfig.id;
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result.data);
      result.status.should.equal(200);
      result.data.should.have.keys([
        'id', 'controller', 'sequence', 'meterId', 'authorization'
      ]);
      let expectedConfig = {
        ...existingConfig,
        ...newConfig
      };
      result.data.should.eql(expectedConfig);

      // retrieve the config using `oauth2` to confirm update was effective
      err = null;
      result = null;
      try {
        result = await helpers.getConfig({id: newConfig.id, accessToken});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.eql(expectedConfig);

      // this update removes `oauth2` authz config
      newConfig = {
        ...existingConfig,
        sequence: 2
      };
      delete newConfig.authorization;
      err = null;
      result = null;
      try {
        const url = existingConfig.id;
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result.data);
      result.status.should.equal(200);
      result.data.should.have.keys([
        'id', 'controller', 'sequence', 'meterId'
      ]);
      expectedConfig = {
        ...existingConfig,
        ...newConfig
      };
      result.data.should.eql(expectedConfig);

      // should fail to retrieve the config since `oauth2` is no longer
      // enabled
      err = null;
      result = null;
      try {
        result = await helpers.getConfig(
          {id: existingConfig.id, accessToken});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');
    });
    it('rejects config update for an invalid zcap', async () => {
      const capabilityAgent2 = await CapabilityAgent.fromSecret(
        {secret: 's2', handle: 'h2'});

      let err;
      let result;
      try {
        result = await helpers.createExchangerConfig({capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);

      const {id: url} = result;
      const newConfig = {
        ...result,
        controller: capabilityAgent2.id,
        sequence: 1
      };

      err = null;
      result = null;
      try {
        // the capability invocation here is signed by `capabilityAgent2`
        // which is not the `controller` of the config
        const zcapClient = helpers.createZcapClient({
          capabilityAgent: capabilityAgent2
        });
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(403);
      err.data.type.should.equal('NotAllowedError');
      err.data.cause.message.should.contain(
        'The capability controller does not match the verification method ' +
        '(or its controller) used to invoke.');
    });
    it('rejects config update with an invalid sequence', async () => {
      const capabilityAgent2 = await CapabilityAgent.fromSecret(
        {secret: 's2', handle: 'h2'});

      let err;
      let result;
      try {
        result = await helpers.createExchangerConfig({capabilityAgent});
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.have.property('id');
      result.should.have.property('sequence');
      result.sequence.should.equal(0);
      const {id: capabilityAgentId} = capabilityAgent;
      result.should.have.property('controller');
      result.controller.should.equal(capabilityAgentId);

      const {id: url} = result;
      const newConfig = {
        ...result,
        controller: capabilityAgent2.id,
        // the proper sequence would be 1
        sequence: 10
      };

      err = null;
      result = null;
      try {
        const zcapClient = helpers.createZcapClient({capabilityAgent});
        result = await zcapClient.write({url, json: newConfig});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.status.should.equal(409);
      err.data.type.should.equal('InvalidStateError');
    });
    describe('updates with ipAllowList', () => {
      it('updates a config with ipAllowList', async () => {
        const capabilityAgent2 = await CapabilityAgent.fromSecret(
          {secret: 's2', handle: 'h2'});

        const ipAllowList = ['127.0.0.1/32', '::1/128'];

        let err;
        let result;
        let existingConfig;
        try {
          existingConfig = result = await helpers.createExchangerConfig(
            {capabilityAgent, ipAllowList});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.have.property('id');
        result.should.have.property('sequence');
        result.sequence.should.equal(0);
        const {id: capabilityAgentId} = capabilityAgent;
        result.should.have.property('controller');
        result.controller.should.equal(capabilityAgentId);

        const {id: url} = result;
        const newConfig = {
          ...existingConfig,
          controller: capabilityAgent2.id,
          ipAllowList,
          sequence: 1
        };

        err = null;
        result = null;
        try {
          const zcapClient = helpers.createZcapClient({capabilityAgent});
          result = await zcapClient.write({url, json: newConfig});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result.data);
        result.status.should.equal(200);
        result.data.should.have.keys([
          'id', 'controller', 'sequence', 'meterId', 'ipAllowList'
        ]);
        const expectedConfig = {
          ...existingConfig,
          ...newConfig
        };
        result.data.should.eql(expectedConfig);

        // should fail to retrieve the config now that controller
        // has changed
        err = null;
        result = null;
        try {
          result = await helpers.getConfig(
            {id: newConfig.id, capabilityAgent});
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.status.should.equal(403);
        err.data.type.should.equal('NotAllowedError');

        // retrieve the config to confirm update was effective
        err = null;
        result = null;
        try {
          result = await helpers.getConfig(
            {id: newConfig.id, capabilityAgent: capabilityAgent2});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.eql(expectedConfig);
      });
      it('returns NotAllowedError for invalid source IP', async () => {
        const capabilityAgent2 = await CapabilityAgent.fromSecret(
          {secret: 's2', handle: 'h2'});

        const ipAllowList = ['8.8.8.8/32'];

        let err;
        let result;
        try {
          result = await helpers.createExchangerConfig(
            {capabilityAgent, ipAllowList});
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.have.property('id');
        result.should.have.property('sequence');
        result.sequence.should.equal(0);
        const {id: capabilityAgentId} = capabilityAgent;
        result.should.have.property('controller');
        result.controller.should.equal(capabilityAgentId);

        const {id: url} = result;
        const newConfig = {
          ...result,
          controller: capabilityAgent2.id,
          ipAllowList,
          sequence: 1
        };

        err = null;
        result = null;
        try {
          const zcapClient = helpers.createZcapClient({capabilityAgent});
          result = await zcapClient.write({url, json: newConfig});
        } catch(e) {
          err = e;
        }
        should.not.exist(result);
        should.exist(err);
        err.status.should.equal(403);
        err.data.type.should.equal('NotAllowedError');
      });
    }); // updates with ipAllowList
  }); // end update config

  describe('revocations', () => {
    it('throws error with invalid zcap when revoking', async () => {
      const config = await helpers.createExchangerConfig({capabilityAgent});
      const zcap = {
        '@context': ['https://w3id.org/zcap/v1'],
        id: 'urn:uuid:895d985c-8e20-11ec-b82f-10bf48838a41',
        proof: {}
      };

      const url =
        `${config.id}/zcaps/revocations/${encodeURIComponent(zcap.id)}`;

      let err;
      let result;
      try {
        result = await httpClient.post(url, {agent, json: zcap});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.data.type.should.equal('ValidationError');
      err.data.message.should.equal(
        'A validation error occurred in the \'Delegated ZCAP\' validator.');
    });
    it('revokes a zcap', async () => {
      const config = await helpers.createExchangerConfig({capabilityAgent});

      const capabilityAgent2 = await CapabilityAgent.fromSecret(
        {secret: 's2', handle: 'h2'});

      const zcap = await helpers.delegate({
        controller: capabilityAgent2.id,
        invocationTarget: config.id,
        delegator: capabilityAgent
      });

      // zcap should work to get config
      const zcapClient = helpers.createZcapClient(
        {capabilityAgent: capabilityAgent2});
      const {data} = await zcapClient.read({capability: zcap});
      data.should.have.keys([
        'controller', 'id', 'sequence', 'meterId'
      ]);
      data.id.should.equal(config.id);

      // revoke zcap
      await helpers.revokeDelegatedCapability({
        serviceObjectId: config.id,
        capabilityToRevoke: zcap,
        invocationSigner: capabilityAgent.getSigner()
      });

      // now getting config should fail
      let err;
      try {
        await zcapClient.read({capability: zcap});
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.data.type.should.equal('NotAllowedError');
    });
  }); // end revocations
});
