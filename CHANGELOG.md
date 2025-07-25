# bedrock-vc-delivery ChangeLog

## 7.4.0 - 2025-07-25

### Changed
- Include enveloped VP schema to useExchangeBody.
- Validate enveloped VP after verification.

## 7.3.0 - 2025-07-03

### Added
- Add support for push notification callback URLs in exchanges. Now if the
  `callback` property of a step is set to an object with a `url` property
  that has a value of an HTTPS URL, this URL will be POSTed to when the
  exchange state changes with a body of: `{event: {data: {exchangeId}}}`.

## 7.2.0 - 2025-06-11

### Added
- Added support for `verifyPresentationOptions` to appear on exchange steps,
  allowing for more extensible and general step option expression.
- Added support for `verifyPresentationResponseSchema` to appear on exchange
  steps, allowing for enforcing validation constraints at the workflow layer.

## 7.1.1 - 2025-04-30

### Changed
- Update dependencies.
- Support node >= 20.

## 7.1.0 - 2025-04-14

### Added
- Replace enveloped VCs with the credentials they envelope in the
  `verifiablePresentation` value in the exchange state variable `results`
  under the current step.

## 7.0.2 - 2025-04-11

### Fixed
- Fix typo in JSON `EnvelopedVerifiableCredential` schema.

## 7.0.1 - 2025-04-11

### Fixed
- Allow `EnvelopedVerifiableCredential` to use a string or an array for its
  `@context` value.

## 7.0.0 - 2025-03-18

### Changed
- Update dependencies.
  - `@digitalbazaar/ed25519-multikey@1.3.1`.
  - `@digitalbazaar/oid4-client@4.3.0`.
  - `@digitalbazaar/vc@7.1.2`.
  - `body-parser@1.20.3`.
  - `jose@5.10.0`.
  - `jsonata@2.0.6`.
  - `serialize-error@12.0.0`.
- Update peer dependencies.
  - `@bedrock/core@6.3.0`.
  - `@bedrock/did-io@10.4.0`.
  - **BREAKING**: `@bedrock/mongodb@11`.
    - Use MongoDB driver 6.x and update error names and details.
    - See changelog for details.
  - `@bedrock/oath2-verifier@2.3.1`.
  - **BREAKING**: `@bedrock/service-agent@10`.
    - Updated for `@bedrock/mongodb@11`.
  - **BREAKING**: `@bedrock/service-core@11`.
    - Updated for `@bedrock/mongodb@11`.
  - `@bedrock/validation@7.1.1`.
- Update dev dependencies.
- Update test dependencies.

## 6.6.2 - 2025-03-04

### Fixed
- Use `result.modifiedCount` to enable newer mongodb driver.
- Remove unused `background` option from mongodb index creation.

## 6.6.1 - 2025-02-28

### Fixed
- Handle case that verifier instance does not return a `presentationResult`.

## 6.6.0 - 2025-02-06

### Added
- Support `jwt_vc_json` and `jwt_vp_json` aliases for `jwt_vc_json-ld`
  and `jwt_vp` for OID4*.
- Support `di_vc` and `di_vp` aliases for `ldp_vc` and `ldp_vp` for OID4*.
- Support non-JSON-encoded `vp_token` values, provided that such a value
  is a JWT, to accommodate OID4* implementations that send bare JWTs
  as `vp_tokens` instead of JSON-encoded JWTs (i.e., JSON strings).

## 6.5.0 - 2025-01-28

### Added
- Allow exchange variables to contain JSON key values that are not
  supported in mongoDB.

## 6.4.1 - 2025-01-27

### Fixed
- Ensure a workflow step that includes `issuanceRequests` and no other
  properties can be executed.

## 6.4.0 - 2024-11-10

### Added
- Add `nonce` endpoint to OID4VCI exchanges.

## 6.3.1 - 2024-11-07

### Fixed
- Remove unnecessary `authorize` "authority" in openid4vp URL.

## 6.3.0 - 2024-10-14

### Added
- Add `issueRequests` feature for expressing parameters for issuing VCs
  in a particular step. The `issueRequest` value must be an array, with
  each element containing parameters for issuing a VC. The parameters
  must minimally include a credential template ID or index that
  references a credential template from the associated workflow. The
  parameters may optionally specify alternative variables to use when
  evaluating the template, either via an object or a string, where
  the string includes the name of a variable from the workflow's
  main `variables`.

## 6.2.0 - 2024-10-02

### Changed
- Update multikey dependencies.

## 6.1.0 - 2024-10-01

### Changed
- Use `@digitalbazaar/oid4-client@4.1` to get latest updates and fixes.

## 6.0.0 - 2024-09-20

### Changed
- **BREAKING**: Use `@digitalbazaar/oid4-client@4` to get fix to
  auto-generated OID4VP authorization requests (use `allOf` JSON
  schema instead of invalid `contains` with an array value).

## 5.6.0 - 2024-09-12

### Added
- Add interaction "protocols" URL support.

## 5.5.1 - 2024-09-05

### Fixed
- Ensure OID4* errors are still logged.

## 5.5.0 - 2024-09-05

### Changed
- Improve OID4* errors and use OID4* error style with `error` and
  `error_description`.

## 5.4.0 - 2024-09-03

### Added
- Allow multiple credentials (if they are of the same type) to be returned
  from a single OID4VCI exchange using the `credential` endpoint (not the
  batch endpoint).

## 5.3.5 - 2024-08-27

### Fixed
- Ensure OID4VP authorization responses (which is sent as a urlencoded
  payload), can be large enough to accommodate most VPs.

## 5.3.4 - 2024-08-26

### Fixed
- Ensure contexts in credential definitions are compared using deep equality
  during OID4VCI.

## 5.3.3 - 2024-08-24

### Fixed
- Improve verification method controller check error.

## 5.3.2 - 2024-08-24

### Fixed
- Allow list specific error keys to include in last error.

## 5.3.1 - 2024-08-24

### Fixed
- Throw better error if DID proof JWT verification method cannot be retrieved
  from `kid` URL.

## 5.3.0 - 2024-08-24

### Added
- Include `expires` in exchange information.
- Include `lastError` in exchange information.

### Changed
- Improve error information on failed exchange requests.

## 5.2.0 - 2024-08-22

### Added
- Add support for creating offers that use `credential_offer_uri`
  for OID4VCI by serving an auto-generated credential offer from
  `<exchangeId>/openid/credential-offer`.

## 5.1.0 - 2024-08-22

### Added
- Add `credential_configurations_supported` to OID4VCI metadata.
- Add `credential_issuer` to OID4VCI metadata.
- Add auto-generated client metadata for OID4VP when it is not
  provided by the exchange creator, using default `vp_formats`.

### Fixed
- Ensure default of 15 minutes is set for exchange TTL.

## 5.0.1 - 2024-08-08

### Fixed
- Fix processing of VC-JWT VPs/VCs in OID4* combined workflows.

## 5.0.0 - 2024-08-05

### Added
- Add support for ECDSA keys (with `ES256` and `ES384` algs) for
  DID JWT proofs.
- Add support for VC 2.0 contexts in JSON schemas.

### Changed
- **BREAKING**: Update peer dependencies.
  - `@bedrock/core@6.1.3`
  - `@bedrock/did-io@10.3.1`
  - `@bedrock/express@8.3.1`
  - `@bedrock/https-agent@4.1.0`
  - `@bedrock/mongodb@10.2.0`
  - `@bedrock/oauth2-verifier@2.1.0`
  - `@bedrock/service-agent@9.0.2`
  - `@bedrock/service-core@10.0.0`
- Update minor, test, and dev dependencies.

### Fixed
- Fix JSON schema to allow VCs with only a single type.

## 4.8.0 - 2024-07-18

### Added
- Add `presentationSchema` option to workflow step to enable passing
  a JSON schema to be run against a submitted presentation.

## 4.7.0 - 2024-07-15

### Added
- Add workflow configuration option to specify `issuerInstances` with
  supported formats (such as `application/vc`, `ldp_vc`, and `jwt_vc_json-ld`
  as well as `zcapReferenceIds` with at least one `issue` reference ID
  that identifies the zcap in the main config `zcaps` map to use to
  issue VCs using that issuer instance. When multiple issuer instances
  are provided, a workflow exchange can accept different requested
  formats from the client.

### Changed
- The supported formats expressed in `issuerInstances` (or the default
  of `ldp_vc` will be used when checking expected credential requests
  during OID4VCI. This behavior doesn't change from the previous
  version because the previous version only allowed `ldp_vc` to be
  included in expected credential requests. Now `jwt_vc_json-ld`
  can also be passed in an expected credential request, but format
  can also be omitted entirely since it is no longer used when checking
  credential requests are valid against the supported list of formats
  from the issuer instances.

## 4.6.0 - 2024-07-01

### Added
- Include `'pre-authorized_grant_anonymous_access_supported': true` to
  OID4VCI issuer config meta data. This flag indicates to clients that
  they do not need to send a `client_id` in their request for credentials.

## 4.5.0 - 2024-06-21

### Added
- Support `Multikey`-typed and `publicKeyJwk`-specified public keys
  in "DID proof JWTs" for OID4VCI.

## 4.4.0 - 2024-06-21

### Added
- Allow an evaluated credential template to produce a VC API issue
  credential request (i.e., including the `credential` param and
  any other optional params) as an optional alternative to returning
  only the value of the `credential` param for issuance.
- Allow clients to provide local workflow IDs as long as they meet
  the local ID validation requirements. This is to enable clients to
  ensure that they do not create duplicate workflows.
- Enable OID4VCI+OID4VP flows that include providing an OID4VP
  authorization request during a credential request that must be
  fulfilled prior to accepting the credential request(s).
- Expose `exchangers` base route as `workflows`, keeping `exchangers` as a
  deprecated alias.
- Allow workflow steps to include a `allowUnprotectedPresentation`
  boolean that determines whether a workflow will accept an unprotected
  presentation. This is useful for enabling the submission of VCs
  to holder workflow services for storage.

### Changed
- Improve errors returned from failed verification during exchanges.
- **NOTE**: Deployment configurations that want an easy path to supporting
  the new `workflows` alias should be updated to change the `vc-exchanger`
  service under `app-identity` to `vc-workflow` to ensure that a service
  agent with development-level credentials is not added to the database.
  Without issuing any meters associated with the `vc-workflow` service
  the `workflows` endpoints will be unusable, but later upgrades to
  allow their use will require removing this erroneous record, so it is
  advisable to make this change prior to updating if the `workflows`
  endpoints are ever intended to be used in a deployment.

## 4.3.0 - 2023-12-11

### Added
- Add support for receiving the `types` property in posted credential
  definitions during OID4VCI even if that does not match the served
  credential definition in the protocol. The property should likely
  be `type` to match the VC data model, but a OID4VCI draft uses
  `types` in an example and clients have implemented this.

## 4.2.0 - 2023-11-28

### Added
- Add extra oauth/openid config `/.well-known` paths to
  accommodate clients that have implemented against what
  is likely an OID4VCI draft bug.

## 4.1.2 - 2023-10-25

### Fixed
- Fix `client_id_scheme` default check.

## 4.1.1 - 2023-10-25

### Fixed
- Fix OID4VP defaults for `client_id` and `client_id_scheme`.

## 4.1.0 - 2023-10-25

### Added
- Add `redirectUrl` feature in VC API exchanges. A `redirectUrl` can
  now be specified in a `step` to be included in the result of the
  step that is passed to the client.
- Add optional OID4VP presentation exchange. The current implementation
  is largely experimental and subject to change, just as the OID4VP spec
  is undergoing rapid development and is in a draft stage. The current
  implementation was written against OID4VP draft 20 and only supports
  a profile of OID4VP that uses data integrity / LDP protected VPs and VCs.

## 4.0.0 - 2023-09-22

### Changed
- **BREAKING**: Update peer deps:
  - Use `@bedrock/oauth2-verifier@2`.
  - Use `@bedrock/service-agent@8`.
  - Use `@bedrock/service-core@9`.
- Update test deps.

## 3.5.1 - 2023-08-30

### Fixed
- Ensure expected `domain` matches value from VPR in exchange.

## 3.5.0 - 2023-08-22

### Added
- Add `stepTemplate` feature. Steps in exchanges may be optionally
  specified as templates that will use the variables from the exchange.

## 3.4.1 - 2023-08-21

### Fixed
- Fix uncaught unrejected promise bug when fetching exchange in parallel.

## 3.4.0 - 2023-08-09

### Added
- Serve OpenID credential issuer metadata from
  `.well-known/openid-credential-issuer` in addition to
  the older / previously used combined metadata config URL:
  `.well-known/oauth-authorization-server`.

## 3.3.0 - 2023-08-03

### Added
- Add `vc-api delivery` and ` VC-API delivery + DID authn` tests
  to issue using `generic` credential template.

### Changed
- Pass binding variables to jsonata `evaluate()` function.

## 3.2.0 - 2023-07-19

### Added
- Add dev application identity for `vc-exchanger`.

## 3.1.1 - 2023-07-19

### Fixed
- Fix meter usage aggregator function.

## 3.1.0 - 2023-07-13

### Added
- Add GET endpoint for getting exchange information from any existing
  exchange, particularly useful for obtaining its current state and
  any user-submitted data.

### Fixed
- Ensure exchanges are updated when steps are completed.

## 3.0.2 - 2023-06-26

### Fixed
- Fix missing dependencies and update old ones.

## 3.0.1 - 2023-06-26

### Fixed
- Fix `package.json` exported files.

## 3.0.0 - 2023-06-04

### Added
- Add "batch credential" endpoint support for OpenID-based VC delivery.
- Add `generateKeyPair` option to `openId.oauth2` when creating VC exchanges.

### Changed
- **BREAKING**: Configurations must use `openId` to specify
  OID4VCI/OID4VC/OID4* options, not `oidc4vci`. This change is incompatible
  with previous versions and any deployed instances must be manually upgraded.
- **BREAKING**: The `/oidc4vci` route has been changed to `/openid`.
- **BREAKING**: Require `expectedCredentialRequests` in `openId` exchanger
  config options. It must be an array with one or more elements with the
  `type` and `format` expected. If more than one element is present, then
  the exchange can only be fulfilled using the "batch credential" endpoint.

## 2.0.0 - 2023-04-18

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/did-io` to v10.0.
  - `@bedrock/service-agent` to v7.0.
  - `@bedrock/service-core` to v8.0.

## 1.0.0 - 2022-11-03

- See git history for changes.
