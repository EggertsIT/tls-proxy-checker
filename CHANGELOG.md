# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.3] - 2026-07-14

### Fixed

- Linux release builds now require the pinned standalone CPython URL and
  SHA-256 digest as explicit metadata inputs, preventing an incomplete
  `BUILDINFO.json` from being published.

### Changed

- Version 0.4.3 is a Linux-only metadata-hardening release. The signed Windows
  version remains 0.4.1 because the Windows executable is unaffected.

## [0.4.2] - 2026-07-14

### Added

- A documented contribution contract and invariant tests for adding or
  modifying inspection profiles.
- A Windows release-packaging script that validates Authenticode and collects
  complete third-party license texts.

### Changed

- Version 0.4.2 is a Linux-only compatibility release. The signed Windows
  version remains 0.4.1 because the Windows executable is unaffected.
- Future release workflows reject lightweight, unsigned, or unverified tags.
- Windows release verification now requires packaged dependency licenses.
- Linux release binaries now build in a digest-pinned PyPA manylinux2014 image
  with a SHA-256-pinned shared CPython distribution and enforce a maximum GLIBC
  requirement of 2.17 instead of 2.35.
- CI now builds and audits the complete Linux x86-64 release artifact on the
  glibc 2.17 baseline.

## [0.4.1] - 2026-07-13

### Added

- Authenticode-signed Windows x86-64 release artifacts and checksum file.
- A Windows-hosted workflow for validating published hashes, signatures,
  archive contents, CLI startup, and live TLS results.

### Fixed

- Corrected the documented minimum GLIBC version for GitHub-built Linux
  binaries from 2.34 to the audited requirement of 2.35.
- Added a release gate that fails if bundled ELF files require a newer GLIBC
  version than the documented compatibility floor.

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

[Unreleased]: https://github.com/EggertsIT/tls-proxy-checker/compare/v0.4.3...HEAD
[0.4.3]: https://github.com/EggertsIT/tls-proxy-checker/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/EggertsIT/tls-proxy-checker/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/EggertsIT/tls-proxy-checker/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/EggertsIT/tls-proxy-checker/releases/tag/v0.4.0
