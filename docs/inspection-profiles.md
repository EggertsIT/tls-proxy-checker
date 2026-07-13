# Inspection Profiles

TLS Proxy Checker separates its product identity from vendor capability data.
An inspection profile describes the protocol and cipher suites a proxy is
documented to support on its proxy-to-server connection.

## `zscaler-zia`

- Provider: Zscaler, Inc.
- Source: [Supported Cipher Suites for SSL/TLS Inspection](https://help.zscaler.com/zia/supported-cipher-suites-ssltls-inspection)
- Last reviewed: 2026-07-13
- Protocols: TLS 1.0, 1.1, 1.2, and 1.3
- Documented cipher suites: 25

The profile preserves the provider's distinction that ECDSA authentication is
supported only on the proxy-to-server side. It also records RSA suites without
Perfect Forward Secrecy separately from PFS-capable suites.

Use it explicitly with:

```bash
tls-proxy-checker example.com --profile zscaler-zia
```

The profile is a reviewed snapshot of public documentation, not a guarantee
that a particular tenant, service edge, policy, license, region, or software
release behaves identically. A compatible result proves endpoint-side protocol
and cipher overlap only. It does not inspect proxy policy, bypass rules,
certificate pinning, authentication flows, or application behavior.

Zscaler is a trademark of Zscaler, Inc. TLS Proxy Checker is independent and is
not affiliated with or endorsed by Zscaler, Inc.

## Profile Contribution Contract

Profiles are maintained security data. A profile change must be traceable to
current primary vendor documentation and must not infer capabilities that the
vendor does not explicitly document.

Each `InspectionProfile` in `src/tls_proxy_checker/profiles.py` contains:

| Field | Requirement |
| --- | --- |
| `id` | Stable lowercase identifier used by the CLI and JSON output. |
| `name` | Human-readable profile name. |
| `provider` | Organization that publishes the capability information. |
| `source_url` | HTTPS URL for the primary vendor documentation. |
| `reviewed_at` | Date the source was checked, in `YYYY-MM-DD` format. |
| `tls_versions` | OpenSSL protocol result names, such as `TLSv1.2`. |
| `tls13_pfs` | Documented TLS 1.3 suite names, such as `TLS_AES_256_GCM_SHA384`. |
| `ecdhe_pfs` | OpenSSL names for documented ECDHE suites through TLS 1.2. |
| `dhe_pfs` | OpenSSL names for documented finite-field DHE suites. |
| `rsa_no_pfs` | Documented static-RSA suites without forward secrecy. |
| `ecdsa_server_side_only` | ECDSA suites restricted to the proxy-to-server side. |

The four capability sets that form `supported_ciphers` must not overlap.
`ecdsa_server_side_only` is a classification overlay and must be a subset of
`ecdhe_pfs`.

## Adding Or Modifying A Profile

1. Locate primary vendor documentation for proxy-to-server TLS behavior. Do
   not use blog posts, search-result summaries, or client-side defaults as the
   capability source.
2. Record the source URL and the date it was reviewed. If the vendor page is
   ambiguous about connection direction, document that limitation instead of
   guessing.
3. Translate TLS 1.2-and-earlier IANA names to the OpenSSL names returned by
   `SSL.Connection.get_cipher_name()`. TLS 1.3 names normally remain in their
   `TLS_*` form.
4. Classify every documented suite by key exchange and authentication. Keep
   unsupported suites out of the capability sets, even when the local OpenSSL
   build can offer them.
5. Add the immutable `InspectionProfile` object and register it in
   `INSPECTION_PROFILES`. Do not change `DEFAULT_PROFILE_ID` as part of adding
   a profile unless that default change is a separately reviewed decision.
6. Add exact contract tests for the documented protocols, supported suites,
   unsupported families, and provider-specific restrictions.
7. Update this page and `CHANGELOG.md`. A material capability change must be
   released because it can change inspection verdicts without changing the
   scanned endpoint.

## Verification

Run the deterministic checks before submitting a profile change:

```bash
python -m pytest -q
python -m bandit -q -r src scripts
python -m tls_proxy_checker.cli example.com --profile PROFILE_ID --json
```

Review the JSON evidence as well as the final verdict. In particular, confirm
that `inspection_profile`, `reason_code`, `proof_source`, and the compatible
cipher evidence all refer to the selected profile. Live endpoint checks are
supplementary because remote configurations can change.
