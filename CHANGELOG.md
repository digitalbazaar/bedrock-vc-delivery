# bedrock-vc-delivery ChangeLog

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
