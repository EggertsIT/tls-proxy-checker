import datetime
import argparse
import json
import socket
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tls_proxy_checker.cli import (
    _cipher_inventory,
    _parse_openssl_msg_output,
    _probe_mtls_application_enforcement,
    assess_inspection_compatibility,
    build_json_output,
    build_batch_output,
    cipher_profile_status,
    detect_mtls,
    inspection_verdict,
    load_targets_from_file,
    main_tls_connect,
    parse_cert_date,
    parse_host,
    probe_cipher,
    probe_protocols,
    probe_inspection_profile,
    run_check,
    validate_cli_paths,
)
from tls_proxy_checker.profiles import ZSCALER_ZIA_PROFILE
from tls_proxy_checker.security import (
    analyze_security,
    hostname_matches,
    parse_certificate_chain,
)


PROFILE = ZSCALER_ZIA_PROFILE


def _build_test_certificate(tmp_path, hostname="localhost", expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now - datetime.timedelta(days=1) if expired else now + datetime.timedelta(days=30)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate, cert_path, key_path


@contextmanager
def _tls12_server(
    cert_path,
    key_path,
    cipher="ECDHE-RSA-AES128-GCM-SHA256",
    require_client_cert=False,
    response=b"",
):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(cipher)
    context.load_cert_chain(cert_path, key_path)
    if require_client_cert:
        context.load_verify_locations(cafile=cert_path)
        context.verify_mode = ssl.CERT_REQUIRED

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 0))
    except PermissionError:
        listener.close()
        pytest.skip("loopback sockets are blocked by the test sandbox")
    listener.listen()
    listener.settimeout(0.1)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                client, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with context.wrap_socket(client, server_side=True) as tls_socket:
                    if response:
                        tls_socket.sendall(response)
            except (ssl.SSLError, OSError):
                client.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)


def test_parse_host_defaults_to_443():
    assert parse_host("https://google.de") == ("google.de", 443)
    assert parse_host("example.com:8443") == ("example.com", 8443)
    assert parse_host("https://example.com/path?q=1") == ("example.com", 443)
    assert parse_host("[2001:db8::1]:8443") == ("2001:db8::1", 8443)


def test_parse_host_rejects_unsafe_or_ambiguous_targets():
    with pytest.raises(ValueError, match="only https"):
        parse_host("http://example.com")
    with pytest.raises(ValueError, match="credentials"):
        parse_host("https://user:password@example.com")
    with pytest.raises(ValueError, match="port"):
        parse_host("example.com:70000")


def test_badssl_coverage_manifest_is_valid():
    manifest = json.loads(
        Path(__file__).with_name("badssl_cases.json").read_text(encoding="utf-8")
    )
    automated = [
        case
        for case in manifest["cases"]
        if case["coverage"].startswith("automated")
    ]
    targets = [case["target"] for case in automated]

    assert len(targets) == len(set(targets))
    assert all(case.get("expected_findings") for case in automated)
    assert all(parse_host(target) for target in targets)


def test_parse_cert_date_handles_double_space_day():
    parsed = parse_cert_date("Jul  1 12:00:00 2026 GMT")
    assert parsed == datetime.datetime(2026, 7, 1, 12, 0, tzinfo=datetime.timezone.utc)


def test_openssl_client_ca_parser_stops_at_next_section():
    output = b"""Acceptable client certificate CA names
C=US, O=Example, CN=Client Root
Client Certificate Types: RSA sign, ECDSA sign
Requested Signature Algorithms: RSA+SHA256:ECDSA+SHA256
"""

    cas, algorithms = _parse_openssl_msg_output(output)

    assert cas == ["C=US, O=Example, CN=Client Root"]
    assert algorithms == ["RSA+SHA256", "ECDSA+SHA256"]


def test_cipher_verdicts_are_stable():
    assert cipher_profile_status("TLS_AES_256_GCM_SHA384", PROFILE) == "supported_pfs"
    assert inspection_verdict("TLS_AES_256_GCM_SHA384", PROFILE) == (
        "can_inspect",
        "CAN INSPECT",
        "green",
    )
    assert inspection_verdict("RC4-SHA", PROFILE)[0] == "cannot_inspect"


def test_inspection_assessment_uses_proven_overlap_and_mtls_override():
    unsupported_connection = {
        "error": None,
        "cipher": {"name": "TLS_AES_128_CCM_SHA256"},
    }
    overlap = {
        "status": "accepted",
        "negotiated_protocol": "TLSv1.2",
        "negotiated_cipher": "ECDHE-RSA-AES128-GCM-SHA256",
    }

    compatible = assess_inspection_compatibility(
        unsupported_connection,
        PROFILE,
        compatibility_probe=overlap,
    )
    assert compatible["inspectable"] is True
    assert compatible["confidence"] == "high"
    assert compatible["proof_source"] == "profile_overlap_probe"
    assert compatible["evidence"]["compatible_cipher"] == (
        "ECDHE-RSA-AES128-GCM-SHA256"
    )

    blocked_by_mtls = assess_inspection_compatibility(
        unsupported_connection,
        PROFILE,
        mtls={"mtls_enforced": True},
        compatibility_probe=overlap,
    )
    assert blocked_by_mtls["inspectable"] is False
    assert blocked_by_mtls["reason_code"] == "mtls_enforced"


def test_inspection_assessment_distinguishes_negative_and_indeterminate():
    connection = {
        "error": None,
        "cipher": {"name": "TLS_AES_128_CCM_SHA256"},
    }

    negative = assess_inspection_compatibility(
        connection,
        PROFILE,
        compatibility_probe={"status": "rejected", "error": "no shared cipher"},
    )
    assert negative["inspectable"] is False
    assert negative["reason_code"] == "no_supported_cipher_overlap"

    indeterminate = assess_inspection_compatibility(
        connection,
        PROFILE,
        compatibility_probe={
            "status": "local_unsupported",
            "error": "backend unavailable",
        },
    )
    assert indeterminate["inspectable"] is None
    assert indeterminate["reason_code"] == "insufficient_evidence"


def test_zscaler_zia_profile_supported_cipher_suites():
    supported_pfs = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-SHA256",
        "DHE-RSA-AES128-SHA256",
        "DHE-RSA-AES256-SHA",
        "DHE-RSA-AES128-SHA",
    }
    ecdsa_server_side_only = {
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-SHA256",
        "ECDHE-ECDSA-AES256-SHA384",
    }
    no_pfs = {
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA",
        "AES128-SHA",
    }

    for cipher in supported_pfs:
        assert cipher_profile_status(cipher, PROFILE) == "supported_pfs"
    for cipher in ecdsa_server_side_only:
        assert cipher_profile_status(cipher, PROFILE) == "ecdsa_server_only"
    for cipher in no_pfs:
        assert cipher_profile_status(cipher, PROFILE) == "no_pfs"

    metadata = PROFILE.as_dict()
    assert metadata["id"] == "zscaler-zia"
    assert metadata["candidate_cipher_count"] == 25
    assert metadata["source_url"].startswith("https://help.zscaler.com/")


def test_zscaler_zia_profile_unsupported_cipher_families():
    unsupported = {
        "EXP-RC4-MD5",
        "DHE-DSS-AES128-SHA",
        "RC4-MD5",
        "RC4-SHA",
        "DES-CBC-SHA",
        "DES-CBC3-SHA",
        "ECDHE-RSA-DES-CBC3-SHA",
    }

    for cipher in unsupported:
        assert cipher_profile_status(cipher, PROFILE) == "not_supported"


def test_cipher_inventory_includes_locally_testable_null_suites():
    names = {item["name"] for item in _cipher_inventory(PROFILE)}
    assert "ECDHE-RSA-NULL-SHA" in names
    assert "NULL-SHA256" in names


def test_json_output_error_shape():
    output = build_json_output(
        "bad.invalid",
        443,
        {"error": "DNS resolution failed"},
        [],
        None,
        PROFILE,
    )
    assert output["schema_version"] == 4
    assert output["inspection_profile"]["id"] == "zscaler-zia"
    assert output["scan_mode"] == "quick"
    assert output["error"] == "DNS resolution failed"
    assert output["host"] == "bad.invalid"
    assert output["port"] == 443
    assert output["security_assessment"]["summary"]["highest_severity"] == "high"


def test_load_targets_from_file_skips_comments_and_blanks(tmp_path):
    targets_file = tmp_path / "urls.txt"
    targets_file.write_text(
        "\n# comment\ngoogle.de\n\nhttps://example.com\n",
        encoding="utf-8",
    )

    assert load_targets_from_file(str(targets_file)) == [
        {"line": 3, "target": "google.de"},
        {"line": 5, "target": "https://example.com"},
    ]


def test_build_batch_output_shape(monkeypatch, tmp_path):
    targets_file = tmp_path / "urls.txt"
    targets_file.write_text("google.de\nbad.invalid\n", encoding="utf-8")

    def fake_run_check(target, args, console=None):
        return {"target": target, "host": target, "port": 443}

    monkeypatch.setattr("tls_proxy_checker.cli.run_check", fake_run_check)
    output = build_batch_output(SimpleNamespace(input_file=str(targets_file)))

    assert output["schema_version"] == 4
    assert output["scan_mode"] == "quick"
    assert output["tool"] == "tls-proxy-checker"
    assert output["inspection_profile"]["id"] == "zscaler-zia"
    assert output["target_count"] == 2
    assert output["results"] == [
        {"target": "google.de", "host": "google.de", "port": 443, "line": 1},
        {"target": "bad.invalid", "host": "bad.invalid", "port": 443, "line": 2},
    ]
    assert output["summary"]["successful_targets"] == 2
    assert output["summary"]["failed_targets"] == 0
    assert output["summary"]["inspection_compatibility"]["indeterminate"] == 2


def test_validate_cli_paths_rejects_missing_input_file():
    parser = argparse.ArgumentParser()
    args = SimpleNamespace(input_file="/tmp/definitely-missing-tls-targets.txt", output_file=None)

    with pytest.raises(SystemExit):
        validate_cli_paths(parser, args)


def test_validate_cli_paths_rejects_missing_output_directory(tmp_path):
    parser = argparse.ArgumentParser()
    args = SimpleNamespace(
        input_file=None,
        output_file=str(tmp_path / "missing" / "report.json"),
    )

    with pytest.raises(SystemExit):
        validate_cli_paths(parser, args)


def test_hostname_matching_uses_san_and_constrained_wildcards():
    assert hostname_matches("api.example.com", ["*.example.com"], [])
    assert not hostname_matches("deep.api.example.com", ["*.example.com"], [])
    assert hostname_matches("192.0.2.1", [], ["192.0.2.1"])
    assert not hostname_matches("192.0.2.2", [], ["192.0.2.1"])


def test_certificate_chain_parser_returns_security_evidence(tmp_path):
    certificate, _cert_path, _key_path = _build_test_certificate(
        tmp_path, hostname="example.com"
    )
    parsed = parse_certificate_chain(
        [certificate.public_bytes(serialization.Encoding.DER)],
        "example.com",
        {"valid": True, "verify_code": None, "error": None},
        now=datetime.datetime.now(datetime.timezone.utc),
    )

    assert parsed["hostname_valid"] is True
    assert parsed["public_key"] == {"type": "RSA", "bits": 2048, "curve": None}
    assert parsed["signature_algorithm"]["hash"] == "sha256"
    assert parsed["extensions"]["extended_key_usage"][0]["oid"] == (
        ExtendedKeyUsageOID.SERVER_AUTH.dotted_string
    )
    json.dumps(parsed)


def test_security_analysis_detects_legacy_and_handshake_issues(tmp_path):
    certificate, _cert_path, _key_path = _build_test_certificate(
        tmp_path, hostname="example.com"
    )
    parsed = parse_certificate_chain(
        [certificate.public_bytes(serialization.Encoding.DER)],
        "example.com",
        {"valid": True, "verify_code": None, "error": None},
    )
    parsed["extensions"]["key_usage_present"] = True
    parsed["extensions"]["key_usage"] = ["cRLSign"]
    conn = {
        "error": None,
        "cipher": {"name": "AES128-SHA", "protocol": "TLSv1.2", "bits": 128},
        "cert": parsed,
        "handshake": {
            "compression": "DEFLATE",
            "secure_renegotiation": None,
            "ephemeral_key": None,
        },
    }
    protocols = [
        {"name": "TLSv1.0", "status": "accepted"},
        {"name": "TLSv1.2", "status": "accepted"},
        {"name": "TLSv1.3", "status": "rejected"},
    ]
    ciphers = [
        {"name": "AES128-SHA", "status": "accepted", "accepted": True, "bits": 128}
    ]

    assessment = analyze_security("example.com", conn, protocols, ciphers, None)
    finding_ids = {finding["id"] for finding in assessment["findings"]}

    assert "TLS-PROTOCOL-LEGACY" in finding_ids
    assert "TLS-CIPHER-CBC" in finding_ids
    assert "TLS-CIPHER-NO-PFS" in finding_ids
    assert "TLS-HANDSHAKE-COMPRESSION" in finding_ids
    assert "TLS-CERT-KEY-USAGE" in finding_ids


def test_security_analysis_detects_weak_dh_parameters():
    conn = {
        "error": None,
        "cipher": {
            "name": "DHE-RSA-AES128-GCM-SHA256",
            "protocol": "TLSv1.2",
            "bits": 128,
        },
        "cert": None,
        "handshake": {
            "compression": None,
            "secure_renegotiation": None,
            "ephemeral_key": {
                "type": "DH",
                "name": "DH",
                "bits": 1024,
                "details": "Peer Temp Key: DH, 1024 bits",
            },
        },
    }

    assessment = analyze_security("example.com", conn, [], [], None)
    finding_ids = {finding["id"] for finding in assessment["findings"]}

    assert "TLS-KEX-WEAK-DH" in finding_ids


def test_security_analysis_uses_vendor_neutral_mtls_finding():
    conn = {
        "error": None,
        "cipher": None,
        "cert": None,
        "handshake": {},
    }
    mtls = {
        "mtls_requested": True,
        "mtls_enforced": True,
        "enforcement_mode": "enforced",
        "enforcement_evidence": "client certificate required",
    }

    assessment = analyze_security("example.com", conn, [], [], mtls)
    finding_ids = {finding["id"] for finding in assessment["findings"]}

    assert "TLS-PROXY-MTLS-ENFORCED" in finding_ids


def test_exact_cipher_and_protocol_probes_use_negotiated_result(tmp_path):
    _certificate, cert_path, key_path = _build_test_certificate(tmp_path)
    with _tls12_server(cert_path, key_path) as (host, port):
        accepted = probe_cipher(
            host,
            port,
            2,
            "ECDHE-RSA-AES128-GCM-SHA256",
            declared_protocol="TLSv1.2",
        )
        rejected = probe_cipher(
            host,
            port,
            2,
            "AES256-SHA",
            declared_protocol="TLSv1.2",
        )
        protocols = probe_protocols(host, port, 2)
        compatibility = probe_inspection_profile(host, port, 2, PROFILE)

    assert accepted["status"] == "accepted", accepted
    assert accepted["negotiated_cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert accepted["bits"] == 128
    assert rejected["status"] == "rejected"
    tls12 = next(item for item in protocols if item["name"] == "TLSv1.2")
    assert tls12["status"] == "accepted"
    assert tls12["negotiated_cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert compatibility["status"] == "accepted", compatibility
    assert compatibility["negotiated_cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"


def test_run_check_defaults_to_quick_mode(monkeypatch):
    connection = {
        "ip": "192.0.2.1",
        "tls_version": "TLSv1.3",
        "cipher": {
            "name": "TLS_AES_256_GCM_SHA384",
            "protocol": "TLSv1.3",
            "bits": 256,
        },
        "cert": None,
        "handshake": {},
        "error": None,
    }
    monkeypatch.setattr(
        "tls_proxy_checker.cli.main_tls_connect",
        lambda *_args, **_kwargs: connection,
    )
    monkeypatch.setattr(
        "tls_proxy_checker.cli.probe_protocols", lambda *_args: []
    )
    monkeypatch.setattr(
        "tls_proxy_checker.cli.detect_mtls",
        lambda *_args: {
            "mtls_requested": False,
            "mtls_enforced": False,
            "method": "test",
        },
    )

    def unexpected_enumeration(*_args, **_kwargs):
        raise AssertionError("quick mode must not enumerate ciphers")

    monkeypatch.setattr(
        "tls_proxy_checker.cli.enumerate_ciphers", unexpected_enumeration
    )
    output = run_check(
        "example.com",
        SimpleNamespace(
            port=None,
            timeout=2,
            json=True,
            full=False,
            no_enum=False,
            no_protocols=False,
            cert=None,
            key=None,
        ),
    )

    assert output["scan_mode"] == "quick"
    assert output["cipher_enumeration"] == []
    assert output["inspection_verdict"]["inspectable"] is True
    assert output["duration_ms"] >= 0


def test_main_handshake_preserves_untrusted_certificate_evidence(tmp_path):
    _certificate, cert_path, key_path = _build_test_certificate(tmp_path)
    with _tls12_server(cert_path, key_path) as (host, port):
        result = main_tls_connect(host, port, 2)

    assert result["error"] is None
    assert result["tls_version"] == "TLSv1.2"
    assert result["cert"]["trust"]["valid"] is False
    assert result["cert"]["hostname_valid"] is False
    assert result["cert"]["public_key"]["type"] == "RSA"
    assert result["cert"]["ocsp_stapling"]["status"] == "absent"
    assessment = analyze_security(host, result, [], [], None)
    finding_ids = {finding["id"] for finding in assessment["findings"]}
    assert "TLS-CERT-UNTRUSTED" in finding_ids
    assert "TLS-CERT-SELF-SIGNED" in finding_ids


def test_cipher_handshake_failure_is_not_mislabeled_as_mtls(tmp_path):
    _certificate, cert_path, key_path = _build_test_certificate(tmp_path)
    with _tls12_server(
        cert_path,
        key_path,
        cipher="ECDHE-RSA-NULL-SHA:@SECLEVEL=0",
    ) as (host, port):
        result = detect_mtls(host, port, 2)

    assert result["mtls_requested"] is False
    assert result["mtls_enforced"] is False


def test_required_client_certificate_is_detected(tmp_path):
    _certificate, cert_path, key_path = _build_test_certificate(tmp_path)
    with _tls12_server(
        cert_path,
        key_path,
        require_client_cert=True,
    ) as (host, port):
        result = detect_mtls(host, port, 2)

    assert result["mtls_requested"] is True
    assert result["mtls_enforced"] is True


def test_http_client_certificate_rejection_is_enforcement(tmp_path):
    _certificate, cert_path, key_path = _build_test_certificate(tmp_path)
    response = (
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 45\r\n\r\n"
        b"No required SSL certificate was sent by client"
    )
    with _tls12_server(cert_path, key_path, response=response) as (host, port):
        enforced, evidence, error = _probe_mtls_application_enforcement(
            host, port, 2
        )

    assert enforced is True
    assert evidence
    assert error is None
