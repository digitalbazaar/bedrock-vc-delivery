/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {agent} from '@bedrock/https-agent';
import express from 'express';
import {fileURLToPath} from 'node:url';
import fs from 'node:fs';
import {httpClient} from '@digitalbazaar/http-client';
import https from 'node:https';
import {mockData} from './mock.data.js';
import path from 'node:path';
import {randomUUID as uuid} from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const key = fs.readFileSync(__dirname + '/key.pem');
const cert = fs.readFileSync(__dirname + '/cert.pem');

function _startServer({app}) {
  return new Promise(resolve => {
    const server = https.createServer({key, cert}, app);
    server.listen(() => {
      return resolve(server);
    });
  });
}

const app = express();
app.use(express.json());

let server;
before(async () => {
  server = await _startServer({app});
});
after(async () => {
  server.close();
});

describe('exchange with enveloped VP and presentationSchema', () => {
  let capabilityAgent;
  let workflowId;
  let workflowRootZcap;
  let zcaps;
  beforeEach(async () => {
    const deps = await helpers.provisionDependencies();
    const {workflowIssueZcap, workflowVerifyPresentationZcap} = deps;
    ({capabilityAgent} = deps);

    // create workflow instance w/ oauth2-based authz
    zcaps = {
      issue: workflowIssueZcap,
      verifyPresentation: workflowVerifyPresentationZcap
    };
  });
  it.only('should pass enveloped VP without presentationSchema', async () => {
    // require semantically-named workflow steps
    const steps = {
      request: {
        createChallenge: false,
        allowUnprotectedPresentation: true,
        verifiablePresentationRequest: mockData.envelopedVpRequest
      }
    };
    // set initial step
    const initialStep = 'request';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent,
      zcaps,
      // credentialTemplates,
      steps,
      initialStep,
      oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.overAgeTokenCredentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });
    // generate VP
    const verifiablePresentation = mockData.envelopedVp;
    // post VP
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    response.status.should.equal(200);
    // exchange should be complete and contain the VP and VC
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        const vp = exchange.variables.results.request.verifiablePresentation;
        should.exist(vp);
        vp.should.be.an('object');
        const {overAge} = vp.verifiableCredential.credentialSubject;
        should.exist(overAge);
        overAge.should.equal(21);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });

  it.only('should pass enveloped VP and presentationSchema', async () => {
    // require semantically-named workflow steps
    const steps = {
      request: {
        createChallenge: false,
        allowUnprotectedPresentation: true,
        presentationSchema: mockData.envelopedVpPresentationSchema,
        verifiablePresentationRequest: mockData.envelopedVpRequest
      }
    };
    // set initial step
    const initialStep = 'request';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent,
      zcaps,
      // credentialTemplates,
      steps,
      initialStep,
      oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.overAgeTokenCredentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });
    // generate VP
    const verifiablePresentation = mockData.envelopedVp;
    // post VP
    const response = await httpClient.post(
      exchangeId, {agent, json: {verifiablePresentation}});
    response.status.should.equal(200);
    // exchange should be complete and contain the VP and VC
    {
      let err;
      try {
        const {exchange} = await helpers.getExchange(
          {id: exchangeId, capabilityAgent});
        should.exist(exchange?.state);
        exchange.state.should.equal('complete');
        const vp = exchange.variables.results.request.verifiablePresentation;
        should.exist(vp);
        vp.should.be.an('object');
        const {overAge} = vp.verifiableCredential.credentialSubject;
        should.exist(overAge);
        overAge.should.equal(21);
      } catch(error) {
        err = error;
      }
      should.not.exist(err);
    }
  });

  it.only('should throw a ValidationError', async () => {
    const mismatchedPresentationSchema = {
      type: 'JsonSchema',
      jsonSchema: {
        title: 'Incorrect Presentation Schema',
        type: 'string',
      }
    };
    // require semantically-named workflow steps
    const steps = {
      request: {
        createChallenge: false,
        allowUnprotectedPresentation: true,
        presentationSchema: mismatchedPresentationSchema,
        verifiablePresentationRequest: mockData.envelopedVpRequest
      }
    };
    // set initial step
    const initialStep = 'request';
    const workflowConfig = await helpers.createWorkflowConfig({
      capabilityAgent,
      zcaps,
      // credentialTemplates,
      steps,
      initialStep,
      oauth2: true
    });
    workflowId = workflowConfig.id;
    workflowRootZcap = `urn:zcap:root:${encodeURIComponent(workflowId)}`;
    const credentialId = `urn:uuid:${uuid()}`;
    const {exchangeId} = await helpers.createCredentialOffer({
      // local target user
      userId: 'urn:uuid:01cc3771-7c51-47ab-a3a3-6d34b47ae3c4',
      credentialDefinition: mockData.overAgeTokenCredentialDefinition,
      credentialId,
      preAuthorized: true,
      userPinRequired: false,
      capabilityAgent,
      workflowId,
      workflowRootZcap
    });
    // generate VP
    const verifiablePresentation = mockData.envelopedVp;
    // post VP
    let err;
    try {
      const response = await httpClient.post(
        exchangeId, {agent, json: {verifiablePresentation}});
      response.status.should.equal(200);
    } catch(error) {
      err = error;
    }
    should.exist(err);
    err.data.name.should.equal('ValidationError');
    const errorDetail = err.data.details.errors[0];
    errorDetail.message.should.equal('should be string');
  });
});
