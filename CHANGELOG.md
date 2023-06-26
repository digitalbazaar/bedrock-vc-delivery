# bedrock-vc-delivery ChangeLog

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
