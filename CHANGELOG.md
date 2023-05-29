# bedrock-vc-delivery ChangeLog

## 3.0.0 - 2023-05-dd

### Changed
- **BREAKING**: Configurations must use `oid4` to specify
  OID4VCI/OID4VC/OID4* options, not `oidc4vci`. This change
  is incompatible with previous versions and any deployed
  instances must be manually upgraded.
- **BREAKING**: The `/oidc4vci` route has been changed to
  `/openid`.

## 2.0.0 - 2023-04-18

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/did-io` to v10.0.
  - `@bedrock/service-agent` to v7.0.
  - `@bedrock/service-core` to v8.0.

## 1.0.0 - 2022-11-03

- See git history for changes.
