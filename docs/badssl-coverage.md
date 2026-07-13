# BadSSL Coverage

BadSSL is a browser/client test site containing TLS endpoint tests, HTTP content tests, and browser-policy tests. A remote TLS scanner cannot truthfully detect every category from a server handshake.

The machine-readable contract is `tests/badssl_cases.json`. It is pinned to the reviewed BadSSL source revision and validated by `scripts/verify_badssl.py`.

## Automated TLS Findings

| BadSSL case | Scanner evidence |
| --- | --- |
| expired | Expired leaf certificate |
| wrong.host | subjectAltName mismatch |
| self-signed | Self-signed leaf and failed path validation |
| untrusted-root | Failed certificate path validation |
| incomplete-chain | Missing issuer/intermediate validation error |
| sha1 / sha1-intermediate | Weak leaf or chain signature algorithm |
| client / client-cert-missing | CertificateRequest and mTLS enforcement |
| cbc | Exact accepted CBC cipher suites |
| null | Exact NULL and anonymous cipher suites |
| static-rsa | Accepted static RSA suites without PFS |
| dh1024 | Observed finite-field DH key size |
| tls-v1-0 / tls-v1-1 | Exact per-version handshakes |

Secure certificate variants such as `no-common-name`, `no-subject`, RSA/ECC key sizes, hash variants, and large SAN lists are recorded as evidence. They are not automatically treated as vulnerabilities when the certificate remains valid for the target.

## Backend-Limited or Planned

| BadSSL case | Limitation |
| --- | --- |
| rc4 / 3des | Modern OpenSSL builds can remove these algorithms; exact confirmation needs a maintained legacy backend. |
| dh-small-subgroup | Requires parsing and validating all finite-field DH parameters. |
| dh-composite | Requires extracting and primality-testing the DH modulus. |
| revoked | Requires validated online OCSP/CRL retrieval or a client-specific revocation set. |
| no-sct | Requires checking embedded, OCSP-stapled, and TLS-extension SCT delivery. |
| invalid-expected-sct | Requires SCT signature validation against a current CT log list. |

## Outside Core TLS Scope

- Mixed content, insecure forms, and HTTP credential fields require an HTTP document crawler.
- HSTS, preload behavior, and HTTP-to-HTTPS upgrades belong to an optional HTTP policy assessment.
- Certificate pinning is application/client policy and cannot be inferred from the remote handshake.
- Browser UI tests, favicon behavior, Safe Browsing, and vendor interception-certificate blocklists are browser state, not generic TLS endpoint properties.

## Running the Gate

```bash
PYTHONPATH=src .venv/bin/python scripts/verify_badssl.py \
  --output badssl-verification.json
```

Run a focused subset with:

```bash
PYTHONPATH=src .venv/bin/python scripts/verify_badssl.py \
  --only expired.badssl.com,null.badssl.com
```

BadSSL explicitly warns that public endpoints can change without notice. The local loopback integration suite remains the deterministic release gate; BadSSL is an additional live interoperability gate.
