# Security Policy

## Supported Versions

Security fixes are provided for the latest release line only.

| Version | Supported |
| --- | --- |
| 0.4.x | Yes |
| Earlier versions | No |

## Reporting a Vulnerability

Use GitHub's **Security > Report a vulnerability** flow for confidential
reports. Do not open a public issue containing exploit details, credentials,
private keys, private hostnames, or non-public scan output.

Include the affected version, operating system, reproduction steps, impact,
and any proposed mitigation. You should receive an acknowledgement within
seven days. A fix timeline depends on severity and reproducibility.

If private vulnerability reporting is temporarily unavailable, open a public
issue that requests a private contact channel without disclosing the issue.

## Scanner Safety

TLS Proxy Checker performs network handshakes and configuration probes. Run it
only against systems you own or are authorized to assess. Reports can contain
hostnames, IP addresses, certificate identities, and infrastructure details;
treat them according to your organization's data-handling policy.
