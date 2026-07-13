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
