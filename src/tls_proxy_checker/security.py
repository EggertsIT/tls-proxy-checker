"""Certificate parsing and evidence-based TLS security findings."""

from __future__ import annotations

import datetime
import ipaddress
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)


FINDING_SCHEMA_VERSION = 1
SECURITY_PROFILE = {
    "id": "modern-tls",
    "version": 1,
    "basis": ["RFC 9325", "RFC 8996", "RFC 9525", "RFC 5280"],
}

REFERENCES = {
    "rfc9325": "https://www.rfc-editor.org/rfc/rfc9325.html",
    "rfc8996": "https://www.rfc-editor.org/rfc/rfc8996.html",
    "rfc9525": "https://www.rfc-editor.org/rfc/rfc9525.html",
    "rfc5280": "https://www.rfc-editor.org/rfc/rfc5280.html",
    "rfc6960": "https://www.rfc-editor.org/rfc/rfc6960.html",
    "rfc7633": "https://www.rfc-editor.org/rfc/rfc7633.html",
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _utc_iso(value: Optional[datetime.datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_attribute(value: Any, modern_name: str, legacy_name: str) -> Optional[datetime.datetime]:
    if hasattr(value, modern_name):
        result = getattr(value, modern_name)
    else:
        result = getattr(value, legacy_name, None)
    if result is not None and result.tzinfo is None:
        result = result.replace(tzinfo=datetime.timezone.utc)
    return result


def _oid_name(oid: x509.ObjectIdentifier) -> str:
    name = getattr(oid, "_name", None)
    return name if name and name != "Unknown OID" else oid.dotted_string


def _public_key_details(public_key: Any) -> dict:
    if isinstance(public_key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": public_key.key_size, "curve": None}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {
            "type": "EC",
            "bits": public_key.key_size,
            "curve": public_key.curve.name,
        }
    if isinstance(public_key, dsa.DSAPublicKey):
        return {"type": "DSA", "bits": public_key.key_size, "curve": None}
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return {"type": "Ed25519", "bits": 128, "curve": "Ed25519"}
    if isinstance(public_key, ed448.Ed448PublicKey):
        return {"type": "Ed448", "bits": 224, "curve": "Ed448"}
    return {"type": type(public_key).__name__, "bits": None, "curve": None}


def _key_usage(cert: x509.Certificate) -> tuple[bool, list[str]]:
    try:
        value = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        return False, []

    enabled = []
    attributes = (
        ("digital_signature", "digitalSignature"),
        ("content_commitment", "contentCommitment"),
        ("key_encipherment", "keyEncipherment"),
        ("data_encipherment", "dataEncipherment"),
        ("key_agreement", "keyAgreement"),
        ("key_cert_sign", "keyCertSign"),
        ("crl_sign", "cRLSign"),
    )
    for attribute, label in attributes:
        if getattr(value, attribute):
            enabled.append(label)
    if value.key_agreement:
        if value.encipher_only:
            enabled.append("encipherOnly")
        if value.decipher_only:
            enabled.append("decipherOnly")
    return True, enabled


def _extended_key_usage(cert: x509.Certificate) -> tuple[bool, list[dict]]:
    try:
        value = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
    except x509.ExtensionNotFound:
        return False, []
    return True, [
        {"oid": item.dotted_string, "name": _oid_name(item)} for item in value
    ]


def _basic_constraints(cert: x509.Certificate) -> dict:
    try:
        value = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        return {
            "present": True,
            "ca": value.ca,
            "path_length": value.path_length,
        }
    except x509.ExtensionNotFound:
        return {"present": False, "ca": False, "path_length": None}


def _tls_features(cert: x509.Certificate) -> list[str]:
    try:
        value = cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE).value
    except x509.ExtensionNotFound:
        return []
    return [getattr(item, "name", str(item)) for item in value]


def _authority_information_access(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        value = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return [], []

    ocsp_urls = []
    issuer_urls = []
    for description in value:
        if not isinstance(description.access_location, x509.UniformResourceIdentifier):
            continue
        if description.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(description.access_location.value)
        elif description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            issuer_urls.append(description.access_location.value)
    return ocsp_urls, issuer_urls


def _crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        value = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return []

    urls = []
    for point in value:
        if point.full_name is None:
            continue
        for name in point.full_name:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return urls


def _sct_count(cert: x509.Certificate) -> int:
    for extension_type in (
        x509.PrecertificateSignedCertificateTimestamps,
        x509.SignedCertificateTimestamps,
    ):
        try:
            return len(cert.extensions.get_extension_for_class(extension_type).value)
        except (x509.ExtensionNotFound, ValueError):
            continue
    return 0


def _certificate_details(
    cert: x509.Certificate, position: int, now: datetime.datetime
) -> dict:
    try:
        signature_hash = cert.signature_hash_algorithm.name
    except (ValueError, AttributeError):
        signature_hash = None

    try:
        dns_sans = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        ip_sans = [
            str(value)
            for value in cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        dns_sans = []
        ip_sans = []

    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    issuer_common_names = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    issuer_orgs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    key_usage_present, key_usage = _key_usage(cert)
    eku_present, eku = _extended_key_usage(cert)
    ocsp_urls, issuer_urls = _authority_information_access(cert)
    not_before = _utc_attribute(cert, "not_valid_before_utc", "not_valid_before")
    not_after = _utc_attribute(cert, "not_valid_after_utc", "not_valid_after")

    return {
        "position": position,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "cn": common_names[0].value if common_names else "",
        "issuer_cn": issuer_common_names[0].value if issuer_common_names else "",
        "issuer_org": issuer_orgs[0].value if issuer_orgs else "",
        "serial_number": format(cert.serial_number, "X"),
        "version": cert.version.name,
        "not_before": _utc_iso(not_before),
        "not_after": _utc_iso(not_after),
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "sans": list(dns_sans),
        "san": {"dns": list(dns_sans), "ip": ip_sans},
        "public_key": _public_key_details(cert.public_key()),
        "signature_algorithm": {
            "name": _oid_name(cert.signature_algorithm_oid),
            "oid": cert.signature_algorithm_oid.dotted_string,
            "hash": signature_hash,
        },
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
        "self_signed": cert.subject == cert.issuer,
        "extensions": {
            "basic_constraints": _basic_constraints(cert),
            "key_usage_present": key_usage_present,
            "key_usage": key_usage,
            "extended_key_usage_present": eku_present,
            "extended_key_usage": eku,
            "tls_features": _tls_features(cert),
            "ocsp_urls": ocsp_urls,
            "ca_issuers_urls": issuer_urls,
            "crl_urls": _crl_urls(cert),
            "sct_count": _sct_count(cert),
        },
    }


def _normalize_dns_name(value: str) -> str:
    return value.rstrip(".").encode("idna").decode("ascii").lower()


def hostname_matches(host: str, dns_sans: list[str], ip_sans: list[str]) -> bool:
    """Match a target against SANs using RFC 9525-style wildcard constraints."""
    try:
        reference_ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        reference_ip = None

    if reference_ip is not None:
        for candidate in ip_sans:
            try:
                if reference_ip == ipaddress.ip_address(candidate):
                    return True
            except ValueError:
                continue
        return False

    try:
        reference = _normalize_dns_name(host)
    except UnicodeError:
        return False

    reference_labels = reference.split(".")
    for candidate in dns_sans:
        candidate = candidate.rstrip(".").lower()
        if candidate.startswith("*."):
            try:
                suffix = _normalize_dns_name(candidate[2:])
            except UnicodeError:
                continue
            suffix_labels = suffix.split(".")
            if len(reference_labels) == len(suffix_labels) + 1 and reference.endswith(
                "." + suffix
            ):
                return True
            continue
        try:
            if reference == _normalize_dns_name(candidate):
                return True
        except UnicodeError:
            continue
    return False


def parse_ocsp_response(response_der: Optional[bytes]) -> dict:
    if not response_der:
        return {
            "status": "absent",
            "response_status": None,
            "certificate_status": None,
        }
    try:
        response = ocsp.load_der_ocsp_response(response_der)
    except ValueError as error:
        return {
            "status": "invalid",
            "response_status": None,
            "certificate_status": None,
            "error": str(error),
        }

    result = {
        "status": "present",
        "response_status": response.response_status.name.lower(),
        "certificate_status": None,
    }
    if response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
        result.update(
            {
                "certificate_status": response.certificate_status.name.lower(),
                "this_update": _utc_iso(
                    _utc_attribute(response, "this_update_utc", "this_update")
                ),
                "next_update": _utc_iso(
                    _utc_attribute(response, "next_update_utc", "next_update")
                ),
                "produced_at": _utc_iso(
                    _utc_attribute(response, "produced_at_utc", "produced_at")
                ),
            }
        )
    return result


def parse_certificate_chain(
    chain_der: list[bytes],
    host: str,
    trust: dict,
    ocsp_stapling: Optional[dict] = None,
    now: Optional[datetime.datetime] = None,
) -> Optional[dict]:
    """Parse a DER chain into stable JSON certificate evidence."""
    certificates = []
    seen = set()
    for der in chain_der:
        if not der:
            continue
        cert = x509.load_der_x509_certificate(der)
        fingerprint = cert.fingerprint(hashes.SHA256())
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        certificates.append(cert)
    if not certificates:
        return None

    now = now or datetime.datetime.now(datetime.timezone.utc)
    details = [
        _certificate_details(cert, index, now)
        for index, cert in enumerate(certificates)
    ]
    leaf = dict(details[0])
    not_before = _utc_attribute(
        certificates[0], "not_valid_before_utc", "not_valid_before"
    )
    not_after = _utc_attribute(
        certificates[0], "not_valid_after_utc", "not_valid_after"
    )
    seconds_left = (not_after - now).total_seconds()
    days_left = int(seconds_left // 86400)

    chain_order_valid = all(
        certificates[index].issuer == certificates[index + 1].subject
        for index in range(len(certificates) - 1)
    )
    leaf.update(
        {
            "days_left": days_left,
            "expired": now > not_after,
            "not_yet_valid": now < not_before,
            "expiring_soon": 0 <= seconds_left < 30 * 86400,
            "hostname_valid": hostname_matches(
                host, leaf["san"]["dns"], leaf["san"]["ip"]
            ),
            "trust": trust,
            "chain_length": len(details),
            "chain_order_valid": chain_order_valid,
            "root_certificate_sent": len(details) > 1 and details[-1]["self_signed"],
            "chain": details,
            "ocsp_stapling": ocsp_stapling
            or {
                "status": "not_tested",
                "response_status": None,
                "certificate_status": None,
            },
        }
    )
    return leaf


def make_finding(
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: dict,
    remediation: str,
    references: list[str],
    confidence: str = "confirmed",
) -> dict:
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "confidence": confidence,
        "evidence": evidence,
        "remediation": remediation,
        "references": references,
    }


def _accepted_cipher_names(cipher_results: list[dict], negotiated: Optional[str]) -> list[str]:
    names = {
        item["name"]
        for item in cipher_results
        if item.get("status") == "accepted" or item.get("accepted") is True
    }
    if negotiated:
        names.add(negotiated)
    return sorted(names)


def _cipher_has_pfs(name: str) -> bool:
    return name.startswith("TLS_") or "ECDHE" in name or name.startswith("DHE-")


def _cipher_uses_cbc(name: str) -> bool:
    if any(token in name for token in ("GCM", "CCM", "CHACHA", "POLY1305")):
        return False
    if any(token in name for token in ("RC4", "3DES", "DES-CBC", "NULL")):
        return False
    return any(token in name for token in ("AES", "CAMELLIA", "ARIA", "SEED", "IDEA"))


def _finding_summary(findings: list[dict]) -> dict:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for item in findings:
        counts[item["severity"]] += 1
    highest = next((name for name in SEVERITY_ORDER if counts[name]), None)
    return {
        "status": "issues_found" if findings else "pass",
        "highest_severity": highest,
        "total": len(findings),
        "counts": counts,
    }


def analyze_security(
    host: str,
    conn: dict,
    protocol_results: list[dict],
    cipher_results: list[dict],
    mtls: Optional[dict],
) -> dict:
    """Create machine-readable findings from collected TLS evidence."""
    findings = []

    if conn.get("error"):
        findings.append(
            make_finding(
                "TLS-CONNECTION-001",
                "high",
                "connection",
                "TLS connection failed",
                "The endpoint could not complete the baseline TLS check.",
                {"error": conn["error"]},
                "Verify DNS, network reachability, the port, and the server TLS configuration.",
                [],
            )
        )

    accepted_protocols = {
        item["name"] for item in protocol_results if item.get("status") == "accepted"
    }
    if "SSLv2" in accepted_protocols:
        findings.append(
            make_finding(
                "TLS-PROTOCOL-SSL2",
                "critical",
                "protocol",
                "SSLv2 is accepted",
                "SSLv2 is obsolete and cryptographically unsafe.",
                {"protocol": "SSLv2"},
                "Disable SSLv2 completely.",
                [REFERENCES["rfc9325"]],
            )
        )
    if "SSLv3" in accepted_protocols:
        findings.append(
            make_finding(
                "TLS-PROTOCOL-SSL3",
                "critical",
                "protocol",
                "SSLv3 is accepted",
                "SSLv3 is obsolete and vulnerable to protocol-level attacks.",
                {"protocol": "SSLv3"},
                "Disable SSLv3 completely.",
                [REFERENCES["rfc9325"]],
            )
        )

    legacy_protocols = sorted(accepted_protocols & {"TLSv1.0", "TLSv1.1"})
    if legacy_protocols:
        findings.append(
            make_finding(
                "TLS-PROTOCOL-LEGACY",
                "high",
                "protocol",
                "Deprecated TLS protocol accepted",
                "TLS 1.0 and TLS 1.1 are formally deprecated.",
                {"protocols": legacy_protocols},
                "Require TLS 1.2 or TLS 1.3.",
                [REFERENCES["rfc8996"], REFERENCES["rfc9325"]],
            )
        )

    if protocol_results and not (accepted_protocols & {"TLSv1.2", "TLSv1.3"}):
        findings.append(
            make_finding(
                "TLS-PROTOCOL-NO-MODERN",
                "high",
                "protocol",
                "No modern TLS protocol confirmed",
                "The scan did not confirm TLS 1.2 or TLS 1.3 support.",
                {"accepted_protocols": sorted(accepted_protocols)},
                "Enable TLS 1.2 and preferably TLS 1.3.",
                [REFERENCES["rfc9325"]],
            )
        )
    elif "TLSv1.2" in accepted_protocols and "TLSv1.3" not in accepted_protocols:
        tls13 = next((item for item in protocol_results if item["name"] == "TLSv1.3"), None)
        if tls13 and tls13.get("status") == "rejected":
            findings.append(
                make_finding(
                    "TLS-PROTOCOL-NO-TLS13",
                    "info",
                    "protocol",
                    "TLS 1.3 is not accepted",
                    "TLS 1.2 can be secure, but TLS 1.3 provides a smaller and safer protocol surface.",
                    {"tls13_status": "rejected"},
                    "Enable TLS 1.3 where client and platform compatibility permit.",
                    [REFERENCES["rfc9325"]],
                )
            )

    negotiated = (conn.get("cipher") or {}).get("name")
    accepted_ciphers = _accepted_cipher_names(cipher_results, negotiated)
    insecure_groups = (
        (
            "TLS-CIPHER-NULL",
            "critical",
            "NULL encryption cipher accepted",
            [name for name in accepted_ciphers if "NULL" in name],
        ),
        (
            "TLS-CIPHER-ANON",
            "critical",
            "Anonymous cipher accepted",
            [
                name
                for name in accepted_ciphers
                if name.startswith(("ADH-", "AECDH-")) or "-ANON-" in name
            ],
        ),
        (
            "TLS-CIPHER-EXPORT",
            "critical",
            "Export-grade cipher accepted",
            [name for name in accepted_ciphers if "EXPORT" in name or name.startswith("EXP-")],
        ),
        (
            "TLS-CIPHER-RC4",
            "high",
            "RC4 cipher accepted",
            [name for name in accepted_ciphers if "RC4" in name],
        ),
        (
            "TLS-CIPHER-DES",
            "high",
            "DES or 3DES cipher accepted",
            [
                name
                for name in accepted_ciphers
                if "3DES" in name or "DES-CBC" in name or "DES-EDE" in name
            ],
        ),
    )
    for finding_id, severity, title, names in insecure_groups:
        if names:
            findings.append(
                make_finding(
                    finding_id,
                    severity,
                    "cipher",
                    title,
                    "The server accepted a cipher suite prohibited by modern TLS guidance.",
                    {"ciphers": names},
                    "Disable the listed cipher suites.",
                    [REFERENCES["rfc9325"]],
                )
            )

    cbc_ciphers = [name for name in accepted_ciphers if _cipher_uses_cbc(name)]
    if cbc_ciphers:
        findings.append(
            make_finding(
                "TLS-CIPHER-CBC",
                "medium",
                "cipher",
                "Legacy CBC cipher accepted",
                "AEAD cipher suites are preferred over CBC suites for modern TLS deployments.",
                {"ciphers": cbc_ciphers},
                "Prefer AES-GCM, AES-CCM, or ChaCha20-Poly1305 cipher suites.",
                [REFERENCES["rfc9325"]],
            )
        )

    no_pfs = [name for name in accepted_ciphers if not _cipher_has_pfs(name)]
    if no_pfs:
        findings.append(
            make_finding(
                "TLS-CIPHER-NO-PFS",
                "medium",
                "cipher",
                "Cipher without forward secrecy accepted",
                "Static key exchange can expose recorded traffic if the server private key is compromised.",
                {"ciphers": no_pfs},
                "Prefer TLS 1.3 or ECDHE-based TLS 1.2 cipher suites.",
                [REFERENCES["rfc9325"]],
            )
        )

    weak_bit_ciphers = sorted(
        {
            item["name"]
            for item in cipher_results
            if (item.get("status") == "accepted" or item.get("accepted") is True)
            and isinstance(item.get("bits"), int)
            and item["bits"] < 128
            and not any(
                token in item["name"]
                for token in ("NULL", "RC4", "3DES", "DES-CBC", "DES-EDE")
            )
        }
    )
    if weak_bit_ciphers:
        findings.append(
            make_finding(
                "TLS-CIPHER-WEAK-BITS",
                "high",
                "cipher",
                "Cipher below 128-bit security accepted",
                "The server accepted a cipher with an insufficient effective key size.",
                {"ciphers": weak_bit_ciphers},
                "Disable cipher suites offering less than 128 bits of security.",
                [REFERENCES["rfc9325"]],
            )
        )

    handshake = conn.get("handshake") or {}
    if handshake.get("compression"):
        findings.append(
            make_finding(
                "TLS-HANDSHAKE-COMPRESSION",
                "high",
                "handshake",
                "TLS compression is enabled",
                "TLS-level compression can expose connections to CRIME-style attacks.",
                {"compression": handshake["compression"]},
                "Disable TLS-level compression.",
                [REFERENCES["rfc9325"]],
            )
        )

    ephemeral_key = handshake.get("ephemeral_key") or {}
    if ephemeral_key.get("type") == "DH" and ephemeral_key.get("bits"):
        dh_bits = ephemeral_key["bits"]
        if dh_bits < 2048:
            findings.append(
                make_finding(
                    "TLS-KEX-WEAK-DH",
                    "critical" if dh_bits < 1024 else "high",
                    "key_exchange",
                    "Finite-field Diffie-Hellman parameters are too small",
                    "The observed DHE group does not meet the 2048-bit minimum baseline.",
                    {"ephemeral_key": ephemeral_key},
                    "Use a standardized 2048-bit or stronger FFDHE group, or prefer ECDHE.",
                    [REFERENCES["rfc9325"]],
                )
            )
    elif ephemeral_key.get("type") == "EC" and ephemeral_key.get("bits"):
        if ephemeral_key["bits"] < 224:
            findings.append(
                make_finding(
                    "TLS-KEX-WEAK-EC",
                    "high",
                    "key_exchange",
                    "Ephemeral elliptic-curve group is too small",
                    "The observed ephemeral EC group is below the modern security baseline.",
                    {"ephemeral_key": ephemeral_key},
                    "Use X25519, P-256, or a stronger approved group.",
                    [REFERENCES["rfc9325"]],
                )
            )

    ephemeral_probe = handshake.get("ephemeral_key_probe") or {}
    ephemeral_error = (ephemeral_probe.get("error") or "").lower()
    if not ephemeral_key and any(
        marker in ephemeral_error
        for marker in ("dh key too small", "bad dh value", "invalid dh")
    ):
        findings.append(
            make_finding(
                "TLS-KEX-UNSAFE-DH",
                "high",
                "key_exchange",
                "TLS backend rejected unsafe Diffie-Hellman parameters",
                "The DHE handshake was rejected because the server parameters failed local safety checks.",
                {"probe": ephemeral_probe},
                "Replace custom DH parameters with a standardized 2048-bit or stronger FFDHE group.",
                [REFERENCES["rfc9325"]],
            )
        )

    cert = conn.get("cert")
    if cert:
        trust = cert.get("trust") or {}
        if trust.get("valid") is False:
            findings.append(
                make_finding(
                    "TLS-CERT-UNTRUSTED",
                    "high",
                    "certificate",
                    "Certificate chain is not trusted",
                    "The local platform could not validate the certificate chain.",
                    {"error": trust.get("error"), "verify_code": trust.get("verify_code")},
                    "Install a publicly trusted certificate and serve all required intermediates.",
                    [REFERENCES["rfc5280"]],
                )
            )
            trust_error = (trust.get("error") or "").lower()
            incomplete_markers = (
                "unable to get local issuer certificate",
                "unable to verify the first certificate",
                "unable to get issuer certificate",
            )
            if any(marker in trust_error for marker in incomplete_markers):
                findings.append(
                    make_finding(
                        "TLS-CERT-INCOMPLETE-CHAIN",
                        "high",
                        "certificate",
                        "Certificate chain is incomplete",
                        "The server did not provide an intermediate needed to build a trusted path.",
                        {"trust_error": trust.get("error")},
                        "Serve the leaf certificate followed by every required intermediate.",
                        [REFERENCES["rfc5280"]],
                    )
                )
        if cert.get("self_signed"):
            findings.append(
                make_finding(
                    "TLS-CERT-SELF-SIGNED",
                    "high" if trust.get("valid") is False else "info",
                    "certificate",
                    "Leaf certificate is self-signed",
                    "The server leaf certificate is its own issuer.",
                    {"subject": cert.get("subject")},
                    "Use a certificate chaining to a trust anchor accepted by the intended clients.",
                    [REFERENCES["rfc5280"]],
                )
            )
        if cert.get("hostname_valid") is False:
            findings.append(
                make_finding(
                    "TLS-CERT-HOSTNAME",
                    "high",
                    "certificate",
                    "Certificate does not match the target",
                    "No certificate subjectAltName matched the requested host.",
                    {"host": host, "san": cert.get("san", {})},
                    "Issue a certificate containing the target DNS name or IP address in subjectAltName.",
                    [REFERENCES["rfc9525"]],
                )
            )
        if not cert.get("san", {}).get("dns") and not cert.get("san", {}).get("ip"):
            findings.append(
                make_finding(
                    "TLS-CERT-NO-SAN",
                    "high",
                    "certificate",
                    "Certificate has no subjectAltName",
                    "Modern TLS service identity validation does not fall back to Common Name.",
                    {"common_name": cert.get("cn", "")},
                    "Reissue the certificate with the service identity in subjectAltName.",
                    [REFERENCES["rfc9525"]],
                )
            )
        if cert.get("expired"):
            findings.append(
                make_finding(
                    "TLS-CERT-EXPIRED",
                    "critical",
                    "certificate",
                    "Certificate has expired",
                    "The leaf certificate is outside its validity period.",
                    {"not_after": cert.get("not_after"), "days_left": cert.get("days_left")},
                    "Renew and deploy the certificate immediately.",
                    [REFERENCES["rfc5280"]],
                )
            )
        elif cert.get("not_yet_valid"):
            findings.append(
                make_finding(
                    "TLS-CERT-NOT-YET-VALID",
                    "high",
                    "certificate",
                    "Certificate is not yet valid",
                    "The leaf certificate validity period has not started.",
                    {"not_before": cert.get("not_before")},
                    "Correct the deployment or system time and use a currently valid certificate.",
                    [REFERENCES["rfc5280"]],
                )
            )
        elif cert.get("expiring_soon"):
            severity = "high" if cert.get("days_left", 30) < 7 else "medium"
            findings.append(
                make_finding(
                    "TLS-CERT-EXPIRING",
                    severity,
                    "certificate",
                    "Certificate expires soon",
                    "The leaf certificate expires within 30 days.",
                    {"not_after": cert.get("not_after"), "days_left": cert.get("days_left")},
                    "Renew and deploy the replacement certificate before expiry.",
                    [REFERENCES["rfc5280"]],
                )
            )

        key = cert.get("public_key") or {}
        if key.get("type") == "RSA" and (key.get("bits") or 0) < 2048:
            findings.append(
                make_finding(
                    "TLS-CERT-WEAK-RSA",
                    "high",
                    "certificate",
                    "RSA certificate key is too small",
                    "RSA keys smaller than 2048 bits do not meet modern public TLS requirements.",
                    {"bits": key.get("bits")},
                    "Replace the certificate with an RSA 2048-bit or stronger key, or an approved EC key.",
                    [REFERENCES["rfc9325"]],
                )
            )
        elif key.get("type") == "EC" and (key.get("bits") or 0) < 256:
            findings.append(
                make_finding(
                    "TLS-CERT-WEAK-EC",
                    "high",
                    "certificate",
                    "Elliptic-curve certificate key is too small",
                    "The certificate uses an elliptic curve below the modern security baseline.",
                    {"bits": key.get("bits"), "curve": key.get("curve")},
                    "Use P-256, P-384, Ed25519, or another approved modern key.",
                    [REFERENCES["rfc9325"]],
                )
            )
        elif key.get("type") == "DSA":
            findings.append(
                make_finding(
                    "TLS-CERT-DSA",
                    "high",
                    "certificate",
                    "DSA certificate key is used",
                    "DSA authentication is obsolete for modern public TLS deployments.",
                    {"bits": key.get("bits")},
                    "Replace the certificate with RSA, ECDSA, or EdDSA.",
                    [REFERENCES["rfc9325"]],
                )
            )

        signature_hash = (cert.get("signature_algorithm") or {}).get("hash")
        if signature_hash == "md5":
            findings.append(
                make_finding(
                    "TLS-CERT-SIGNATURE-MD5",
                    "critical",
                    "certificate",
                    "Certificate uses an MD5 signature",
                    "MD5 certificate signatures are cryptographically broken.",
                    {"signature_algorithm": cert.get("signature_algorithm")},
                    "Reissue the certificate using SHA-256 or stronger.",
                    [REFERENCES["rfc9325"]],
                )
            )
        elif signature_hash == "sha1":
            findings.append(
                make_finding(
                    "TLS-CERT-SIGNATURE-SHA1",
                    "high",
                    "certificate",
                    "Certificate uses a SHA-1 signature",
                    "SHA-1 certificate signatures are not acceptable for modern public TLS.",
                    {"signature_algorithm": cert.get("signature_algorithm")},
                    "Reissue the certificate using SHA-256 or stronger.",
                    [REFERENCES["rfc9325"]],
                )
            )

        weak_chain_signatures = [
            {
                "position": item["position"],
                "subject": item["subject"],
                "signature_algorithm": item["signature_algorithm"],
            }
            for item in cert.get("chain", [])[1:]
            if (item.get("signature_algorithm") or {}).get("hash") in {"md5", "sha1"}
        ]
        if weak_chain_signatures:
            severity = (
                "critical"
                if any(
                    item["signature_algorithm"].get("hash") == "md5"
                    for item in weak_chain_signatures
                )
                else "high"
            )
            findings.append(
                make_finding(
                    "TLS-CERT-CHAIN-WEAK-SIGNATURE",
                    severity,
                    "certificate",
                    "Certificate chain uses a weak signature algorithm",
                    "An intermediate certificate is signed with MD5 or SHA-1.",
                    {"certificates": weak_chain_signatures},
                    "Deploy a chain whose certificates use SHA-256 or stronger signatures.",
                    [REFERENCES["rfc9325"], REFERENCES["rfc5280"]],
                )
            )

        extensions = cert.get("extensions") or {}
        if (extensions.get("basic_constraints") or {}).get("ca"):
            findings.append(
                make_finding(
                    "TLS-CERT-LEAF-IS-CA",
                    "high",
                    "certificate",
                    "Leaf certificate is marked as a CA",
                    "A TLS server leaf certificate should not assert CA capability.",
                    {"basic_constraints": extensions.get("basic_constraints")},
                    "Deploy an end-entity certificate with CA set to false.",
                    [REFERENCES["rfc5280"]],
                )
            )

        if extensions.get("extended_key_usage_present"):
            eku_oids = {item["oid"] for item in extensions.get("extended_key_usage", [])}
            allowed = {
                ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE.dotted_string,
            }
            if eku_oids.isdisjoint(allowed):
                findings.append(
                    make_finding(
                        "TLS-CERT-EKU",
                        "high",
                        "certificate",
                        "Certificate is not valid for TLS server authentication",
                        "The Extended Key Usage extension excludes server authentication.",
                        {"extended_key_usage": extensions.get("extended_key_usage")},
                        "Issue a certificate containing the serverAuth Extended Key Usage.",
                        [REFERENCES["rfc5280"]],
                    )
                )

        if extensions.get("key_usage_present"):
            key_usage = set(extensions.get("key_usage", []))
            server_key_usages = {"digitalSignature", "keyEncipherment", "keyAgreement"}
            if key_usage.isdisjoint(server_key_usages):
                findings.append(
                    make_finding(
                        "TLS-CERT-KEY-USAGE",
                        "high",
                        "certificate",
                        "Certificate key usage excludes TLS server authentication",
                        "The Key Usage extension does not permit signing or TLS key establishment.",
                        {"key_usage": sorted(key_usage)},
                        "Issue a server certificate with an appropriate Key Usage extension.",
                        [REFERENCES["rfc5280"]],
                    )
                )

        invalid_chain_certificates = [
            {
                "position": item["position"],
                "subject": item["subject"],
                "not_before": item["not_before"],
                "not_after": item["not_after"],
            }
            for item in cert.get("chain", [])[1:]
            if item.get("expired") or item.get("not_yet_valid")
        ]
        if invalid_chain_certificates:
            findings.append(
                make_finding(
                    "TLS-CERT-CHAIN-VALIDITY",
                    "high",
                    "certificate",
                    "Certificate chain contains an invalid intermediate",
                    "An intermediate certificate is expired or not yet valid.",
                    {"certificates": invalid_chain_certificates},
                    "Replace the invalid intermediate and deploy the corrected chain.",
                    [REFERENCES["rfc5280"]],
                )
            )

        if cert.get("chain_order_valid") is False:
            findings.append(
                make_finding(
                    "TLS-CERT-CHAIN-ORDER",
                    "high",
                    "certificate",
                    "Certificate chain is incorrectly ordered",
                    "The presented certificate issuers and subjects are not in leaf-to-root order.",
                    {"chain_length": cert.get("chain_length")},
                    "Serve the leaf first, followed by each required intermediate certificate.",
                    [REFERENCES["rfc5280"]],
                )
            )
        if cert.get("root_certificate_sent"):
            findings.append(
                make_finding(
                    "TLS-CERT-ROOT-SENT",
                    "info",
                    "certificate",
                    "Server sends a root certificate",
                    "Trust anchors are supplied by clients and do not need to be transmitted.",
                    {"chain_length": cert.get("chain_length")},
                    "Remove the self-signed root certificate from the served chain.",
                    [REFERENCES["rfc5280"]],
                )
            )

        ocsp_result = cert.get("ocsp_stapling") or {}
        must_staple = "status_request" in extensions.get("tls_features", [])
        if must_staple and ocsp_result.get("status") != "present":
            findings.append(
                make_finding(
                    "TLS-CERT-MUST-STAPLE",
                    "high",
                    "certificate",
                    "Must-Staple certificate has no OCSP response",
                    "The certificate requires a stapled OCSP response, but none was observed.",
                    {"ocsp_stapling": ocsp_result},
                    "Configure valid OCSP stapling or replace the Must-Staple certificate.",
                    [REFERENCES["rfc7633"]],
                )
            )
        if ocsp_result.get("certificate_status") == "revoked":
            findings.append(
                make_finding(
                    "TLS-CERT-REVOKED",
                    "critical",
                    "certificate",
                    "Stapled OCSP response reports revocation",
                    "The server stapled an OCSP response marking the certificate revoked.",
                    {"ocsp_stapling": ocsp_result},
                    "Replace the revoked certificate immediately.",
                    [REFERENCES["rfc6960"]],
                )
            )

    if mtls and mtls.get("mtls_enforced"):
        findings.append(
            make_finding(
                "TLS-PROXY-MTLS-ENFORCED",
                "high",
                "proxy_inspection",
                "Endpoint enforces mutual TLS",
                "TLS interception cannot complete client authentication without the client private key.",
                {
                    "enforcement_mode": mtls.get("enforcement_mode"),
                    "enforcement_evidence": mtls.get("enforcement_evidence"),
                },
                "Use an SSL inspection bypass for this endpoint or an approved mTLS design.",
                [],
            )
        )

    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["id"]))
    limitations = []
    if not protocol_results:
        limitations.append("Per-protocol probing was not performed.")
    if not cipher_results:
        limitations.append("Cipher enumeration was not performed; cipher findings use only the negotiated suite.")
    if handshake.get("secure_renegotiation") is None:
        limitations.append("Secure renegotiation support was not testable with the active TLS backend.")
    if handshake.get("ephemeral_key") is None:
        limitations.append("Ephemeral key group and size were not testable with the active TLS backend.")
    if cert and (cert.get("ocsp_stapling") or {}).get("status") in {
        "not_tested",
        "unavailable",
    }:
        limitations.append("OCSP stapling was not testable with the active TLS backend.")
    limitations.append("Exploit-style vulnerability probes and TLS 1.3 0-RTT testing are not performed.")

    return {
        "finding_schema_version": FINDING_SCHEMA_VERSION,
        "profile": SECURITY_PROFILE,
        "summary": _finding_summary(findings),
        "findings": findings,
        "limitations": limitations,
    }
