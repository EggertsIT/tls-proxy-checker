# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-07-13

### Changed

- Renamed the application and Python package to TLS Proxy Checker.
- Replaced vendor-specific JSON field names and finding IDs with neutral names.
- Moved the documented cipher matrix into the explicit `zscaler-zia` profile.
- Bumped the JSON report schema from version 3 to version 4.

### Added

- Profile metadata in single-target and batch JSON reports.
- GitHub CI, dependency update configuration, issue forms, security policy, and
  tag-driven Linux release automation.
- Apache License 2.0 licensing and release artifact provenance attestations.

### Compatibility

- The command is now `tls-proxy-checker`.
- The Python import package is now `tls_proxy_checker`.
- `mtls.zscaler_impact` is now `mtls.inspection_impact`.
- Cipher entries use `profile_status` instead of `zscaler_status`.
- The mTLS finding ID is now `TLS-PROXY-MTLS-ENFORCED`.

[Unreleased]: https://github.com/EggertsIT/tls-proxy-checker/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/EggertsIT/tls-proxy-checker/releases/tag/v0.4.0
