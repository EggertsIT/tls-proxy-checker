# TLS Proxy Checker

[![CI](https://github.com/EggertsIT/tls-proxy-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/EggertsIT/tls-proxy-checker/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

TLS Proxy Checker is a vendor-neutral Linux CLI for two troubleshooting tasks:

1. Prove whether an HTTPS endpoint has protocol and cipher overlap with a
   selected security-proxy inspection profile.
2. Diagnose certificate, chain, hostname, validity, key, protocol, cipher, and
   mutual-TLS issues that commonly break HTTPS connections.

The application is independent. Vendor names appear only in named capability
profiles that cite their public source documentation.

## Install on Linux

Standalone release binaries include Python and all Python dependencies. Python
is not required on the target system.

```bash
VERSION=0.4.0
curl -LO "https://github.com/EggertsIT/tls-proxy-checker/releases/download/v${VERSION}/tls-proxy-checker-${VERSION}-linux-x86_64.tar.gz"
curl -LO "https://github.com/EggertsIT/tls-proxy-checker/releases/download/v${VERSION}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf "tls-proxy-checker-${VERSION}-linux-x86_64.tar.gz"
sudo install -m 0755 tls-proxy-checker /usr/local/bin/tls-proxy-checker
tls-proxy-checker --version
```

The Linux x86-64 build targets glibc 2.34 or newer. Every release includes a
checksum file, build metadata, a GLIBC symbol report, a CycloneDX SBOM, and a
GitHub artifact attestation. With the GitHub CLI installed, provenance can be
verified before installation:

```bash
gh attestation verify "tls-proxy-checker-${VERSION}-linux-x86_64.tar.gz" \
  --repo EggertsIT/tls-proxy-checker
```

## Usage

```bash
tls-proxy-checker google.de
tls-proxy-checker https://example.com
tls-proxy-checker example.com --port 8443
tls-proxy-checker example.com --json
tls-proxy-checker example.com --output-file report.json
tls-proxy-checker example.com --full
tls-proxy-checker example.com --no-protocols
tls-proxy-checker mtls.example.com --cert client.pem --key client.key
tls-proxy-checker --input-file urls.txt --output-file report.json
```

The default quick scan performs the baseline handshake, certificate analysis,
protocol probes, mTLS detection, and one targeted profile-overlap probe when
needed. Use `--full` for exhaustive cipher and weak-suite diagnostics.

Run `tls-proxy-checker --help` for the complete command reference.

## Batch Reports

Input files contain one target per line. Empty lines and lines beginning with
`#` are ignored:

```text
# production endpoints
google.de
https://example.com
api.example.com:8443
```

Batch mode writes one schema-versioned JSON document with all target results,
aggregate certificate findings, and inspection compatibility counts. Output
files are replaced atomically after the complete report is ready.

## Inspection Profiles

Version 0.4.0 includes the `zscaler-zia` profile, based on Zscaler's documented
proxy-to-server protocol and cipher support:

```bash
tls-proxy-checker example.com --profile zscaler-zia
```

Profile data is kept separate from the application identity. A compatible
verdict proves endpoint-side overlap with the selected profile; it does not
prove that a tenant policy will inspect the traffic. Proxy bypass rules,
licenses, regional behavior, certificate pinning, and application-layer
authentication remain outside that verdict. See
[Inspection Profiles](docs/inspection-profiles.md) for source and scope details.

## Security Checks

- Certificate trust, hostname, SAN, validity, chain order, and intermediate
  validity
- Public-key type and size, signature algorithm, Key Usage, and Extended Key
  Usage
- OCSP stapling and Must-Staple evidence when supported by the TLS backend
- SSLv3 and TLS 1.0 through TLS 1.3 protocol probes
- Profile-specific cipher overlap and mTLS interception blockers
- Deprecated protocols, weak ciphers, CBC, missing PFS, and TLS compression
- Exact TLS 1.2 and TLS 1.3 cipher enumeration in full mode
- Stable finding IDs with severity, confidence, evidence, remediation, and
  standards references

The scanner performs TLS handshakes and configuration probes. It does not send
exploit payloads. Run it only against systems you own or are authorized to
assess. See [Security Policy](SECURITY.md).

## Known Limits

Modern OpenSSL builds may not be able to offer removed legacy algorithms such
as RC4 or 3DES. Reliable revocation testing requires validated online OCSP or
CRL retrieval, and certificate-transparency validation requires a current CT
log list. Browser policy, HTTP mixed content, HSTS, pinning, and application
behavior cannot be inferred from a remote TLS handshake.

[BadSSL Coverage](docs/badssl-coverage.md) documents the deterministic,
backend-limited, and out-of-scope cases in detail.

## Development

```bash
git clone git@github.com:EggertsIT/tls-proxy-checker.git
cd tls-proxy-checker
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,build]"
python -m pytest
python -m bandit -q -r src scripts
python -m pip_audit
python -m build
```

Build the standalone executable on the target operating-system family and
architecture:

```bash
make build
./dist/tls-proxy-checker --version
```

See [Contributing](CONTRIBUTING.md) and the [Changelog](CHANGELOG.md).

## Release Process

Tagging `vMAJOR.MINOR.PATCH` runs the tests, security checks, dependency audit,
Linux PyInstaller build, smoke tests, GLIBC audit, SBOM generation, checksums,
artifact attestation, and GitHub Release creation. The tag must match both
version declarations.

```bash
python scripts/verify_release_version.py v0.4.0
git tag -s v0.4.0
git push origin v0.4.0
```

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Roman Eggerts.

Zscaler is a trademark of Zscaler, Inc. TLS Proxy Checker is not affiliated
with or endorsed by Zscaler, Inc.
