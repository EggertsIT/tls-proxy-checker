#!/usr/bin/env python3
"""TLS proxy compatibility and certificate diagnostics."""

import ssl
import socket
import datetime
import argparse
import json
import ipaddress
import os
import re
import select
import shutil
import subprocess  # nosec B404
import tempfile
import time
from contextlib import suppress
from typing import Optional
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.serialization import Encoding

from tls_proxy_checker import __version__
from tls_proxy_checker.profiles import (
    DEFAULT_PROFILE_ID,
    INSPECTION_PROFILES,
    InspectionProfile,
    get_inspection_profile,
)
from tls_proxy_checker.security import (
    analyze_security,
    parse_certificate_chain,
    parse_ocsp_response,
)

HELP_EPILOG = """Examples:
  tls-proxy-checker google.de
  tls-proxy-checker https://example.com
  tls-proxy-checker --input-file urls.txt
  tls-proxy-checker --input-file urls.txt --output-file report.json
  tls-proxy-checker example.com --port 8443
  tls-proxy-checker example.com --timeout 10
  tls-proxy-checker example.com --json
  tls-proxy-checker example.com --full
  tls-proxy-checker mtls.example.com --cert client.pem --key client.key

Output includes:
  - Fast security-proxy TLS compatibility verdict
  - Per-version protocol support and certificate diagnostics
  - Optional exhaustive cipher-suite probes with --full
  - Certificate trust, identity, chain, key, signature, SANs, and expiry
  - Structured security findings with severity, evidence, and remediation
  - mTLS/client-certificate detection
  - Configured inspection-profile verdict and recommended action

Batch input files contain one target per line. Empty lines and lines starting
with # are ignored.
"""

# ---------------------------------------------------------------------------
# Rich import with graceful fallback
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ---------------------------------------------------------------------------
# pyOpenSSL import with graceful fallback
# ---------------------------------------------------------------------------
try:
    from OpenSSL import SSL
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False

WEAK_CIPHER_CANDIDATES = {
    "ECDHE-ECDSA-NULL-SHA",
    "ECDHE-RSA-NULL-SHA",
    "NULL-SHA256",
    "NULL-SHA",
    "NULL-MD5",
    "ADH-AES256-GCM-SHA384",
    "ADH-AES128-GCM-SHA256",
    "ADH-AES256-SHA256",
    "ADH-AES128-SHA256",
    "ADH-AES256-SHA",
    "ADH-AES128-SHA",
    "AECDH-AES256-SHA",
    "AECDH-AES128-SHA",
    "DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "RC4-SHA",
    "RC4-MD5",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_host(target: str, default_port: int = 443) -> tuple[str, int]:
    """Parse an HTTPS URL or host target, including IPv4 and IPv6."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target is empty")
    if not 1 <= default_port <= 65535:
        raise ValueError("default port must be between 1 and 65535")

    raw_target = target.strip()
    if any(ord(char) < 32 or char.isspace() for char in raw_target):
        raise ValueError("target contains whitespace or control characters")

    if "://" not in raw_target:
        try:
            direct_ip = ipaddress.ip_address(raw_target.strip("[]"))
        except ValueError:
            direct_ip = None
        if direct_ip is not None:
            return str(direct_ip), default_port
        parsed = urlsplit("//" + raw_target)
    else:
        parsed = urlsplit(raw_target)
        if parsed.scheme.lower() != "https":
            raise ValueError("only https:// URLs or bare hostnames are supported")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials are not allowed in targets")
    if not parsed.hostname:
        raise ValueError("target does not contain a hostname")

    try:
        port = parsed.port if parsed.port is not None else default_port
    except ValueError as error:
        raise ValueError(f"invalid port: {error}") from error
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    host = parsed.hostname.rstrip(".")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("hostname is not valid IDNA") from error
        if len(host) > 253 or any(not label or len(label) > 63 for label in host.split(".")):
            raise ValueError("hostname is invalid or too long")
    return host, port


def get_cert_san(cert: dict) -> list:
    """Extract Subject Alternative Names from a decoded cert dict."""
    sans = []
    for ext_type, value in cert.get("subjectAltName", []):
        if ext_type == "DNS":
            sans.append(value)
    return sans


def format_host_port(host: str, port: int) -> str:
    """Format a host and port for OpenSSL, including bracketed IPv6."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{port}"
    if address.version == 6:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def parse_cert_date(date_str: str) -> datetime.datetime:
    """Parse the notBefore / notAfter strings returned by ssl."""
    try:
        return datetime.datetime.strptime(
            date_str.strip(), "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return datetime.datetime.strptime(
            date_str.strip(), "%b  %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)


def cipher_profile_status(
    cipher_name: str,
    profile: InspectionProfile,
) -> str:
    """Classify a cipher against the selected inspection profile."""
    return profile.cipher_status(cipher_name)


# ---------------------------------------------------------------------------
# mTLS detection helpers
# ---------------------------------------------------------------------------

def _parse_openssl_msg_output(stdout_bytes: bytes) -> tuple:
    """
    Parse output from: openssl s_client -connect host:port -msg
    Returns (acceptable_cas: list[str], requested_sig_algs: list[str])
    """
    acceptable_cas = []
    requested_sig_algs = []

    try:
        text = stdout_bytes.decode(errors="replace")
    except Exception:
        return acceptable_cas, requested_sig_algs

    lines = text.splitlines()
    in_ca_block = False
    for i, line in enumerate(lines):
        # Detect start of CA names block
        if "acceptable client certificate ca names" in line.lower():
            in_ca_block = True
            continue
        if in_ca_block:
            stripped = line.strip()
            # Block ends at empty line or a line that starts a new section
            if stripped == "" or stripped.lower().startswith(
                ("client certificate types:", "requested signature")
            ):
                in_ca_block = False
                # fall through to check for sig algs on same line
            elif stripped.lower() in ("(none)", "none"):
                in_ca_block = False
                continue
            else:
                acceptable_cas.append(stripped)
                continue

        # Requested Signature Algorithms line (may appear as
        # "Requested Signature Algorithms: ECDSA+SHA256:RSA-PSS+SHA256:..." )
        if line.strip().lower().startswith("requested signature algorithms:"):
            # everything after the colon
            _, _, rest = line.partition(":")
            algs = [a.strip() for a in rest.strip().split(":") if a.strip()]
            requested_sig_algs.extend(algs)

    return acceptable_cas, requested_sig_algs


def _run_openssl_msg(host: str, port: int, timeout: int = 10) -> tuple:
    """
    Run: openssl s_client -connect host:port -msg
    Returns (acceptable_cas, requested_sig_algs, success: bool)
    """
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        return [], [], False

    try:
        result = subprocess.run(
            [openssl_path, "s_client", "-connect", format_host_port(host, port), "-msg",
             "-servername", host],
            input=b"",
            capture_output=True,
            timeout=timeout,
        )  # nosec B603
        # openssl writes most output to stderr when using -msg
        combined = result.stdout + result.stderr
        cas, algs = _parse_openssl_msg_output(combined)
        return cas, algs, True
    except FileNotFoundError:
        # openssl not in PATH
        return [], [], False
    except subprocess.TimeoutExpired:
        return [], [], False
    except Exception:
        return [], [], False


# ---------------------------------------------------------------------------
# mTLS detection
# ---------------------------------------------------------------------------

def _probe_mtls_application_enforcement(
    host: str, port: int, timeout: float
) -> tuple[bool, Optional[str], Optional[str]]:
    """Confirm TLS 1.3 mTLS alerts that arrive after application data."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    request = (
        f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                tls_socket.sendall(request)
                response = bytearray()
                while len(response) < 8192:
                    try:
                        chunk = tls_socket.recv(min(2048, 8192 - len(response)))
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    response.extend(chunk)
                response_bytes = bytes(response)
                response_text = response_bytes.decode(errors="replace")
                response_lower = response_text.lower()
                certificate_markers = (
                    "no required ssl certificate was sent",
                    "client certificate required",
                    "client certificate is required",
                    "certificate required",
                )
                if response_bytes.startswith(b"HTTP/"):
                    status_line = response_text.splitlines()[0]
                    if any(marker in response_lower for marker in certificate_markers):
                        return True, f"client-certificate rejection: {status_line}", None
                    return False, f"HTTP response received: {status_line}", None
                if response_bytes == b"":
                    return True, "connection closed after CertificateRequest", None
                return False, "application data received without a client certificate", None
    except ssl.SSLError as error:
        return True, f"post-handshake TLS alert: {error}", None
    except (ConnectionResetError, BrokenPipeError) as error:
        return True, f"connection rejected after CertificateRequest: {error}", None
    except socket.timeout:
        return False, None, "post-handshake mTLS probe timed out"
    except OSError as error:
        return False, None, f"post-handshake mTLS probe failed: {error}"


def detect_mtls(host, port, timeout=5):
    """
    Attempt to detect if the server requests a client certificate (mTLS).
    Returns a dict:
      {
        "mtls_requested": bool,       # server sent CertificateRequest
        "mtls_enforced": bool,        # connection failed without client cert (hard mTLS)
        "method": "pyopenssl" | "ssl_fallback" | "unavailable",
        "error": str or None,
        "acceptable_cas": list[str],  # CA DNs from CertificateRequest
        "requested_sig_algs": list[str],  # sig algs from CertificateRequest
        "enforcement_mode": str,      # "enforced" | "requested_not_enforced" | "none"
        "inspection_impact": str,       # human-readable proxy impact
        "recommendation": str,        # recommended action
      }
    """
    # -----------------------------------------------------------------------
    # Step 1: Determine mtls_requested + mtls_enforced via pyOpenSSL / stdlib
    # -----------------------------------------------------------------------
    if not HAS_PYOPENSSL:
        result = {"mtls_requested": False, "mtls_enforced": False,
                  "method": "ssl_fallback", "error": None,
                  "acceptable_cas": [], "requested_sig_algs": [],
                  "enforcement_evidence": None,
                  "enforcement_mode": "none", "inspection_impact": "",
                  "recommendation": ""}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    pass  # connected fine without client cert
        except ssl.SSLError as e:
            msg = str(e).lower()
            if any(
                marker in msg
                for marker in (
                    "certificate required",
                    "bad certificate",
                    "peer did not return a certificate",
                )
            ):
                result["mtls_enforced"] = True
                result["mtls_requested"] = True
            result["error"] = str(e)
        except Exception as e:
            result["error"] = str(e)
    else:
        # pyOpenSSL path -- intercept CertificateRequest via info_callback
        result = {"mtls_requested": False, "mtls_enforced": False,
                  "method": "pyopenssl", "error": None,
                  "acceptable_cas": [], "requested_sig_algs": [],
                  "enforcement_evidence": None,
                  "enforcement_mode": "none", "inspection_impact": "",
                  "recommendation": ""}

        cert_requested = {"value": False}

        def info_callback(conn, where, ret):
            if where & SSL.SSL_CB_CONNECT_LOOP:
                state = conn.get_state_string().decode(errors="replace").lower()
                if ("certificate request" in state or
                        "ssv3 read server certificate request" in state):
                    cert_requested["value"] = True

        try:
            ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
            ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
            ctx.set_info_callback(info_callback)

            raw = socket.create_connection((host, port), timeout=timeout)
            conn = SSL.Connection(ctx, raw)
            server_name = _sni_bytes(host)
            if server_name:
                conn.set_tlsext_host_name(server_name)
            conn.set_connect_state()
            try:
                _do_openssl_handshake(conn, raw, timeout)
            except SSL.Error:
                pass  # handshake may fail if server truly enforces mTLS
            finally:
                result["mtls_requested"] = cert_requested["value"]
                try:
                    conn.close()
                except Exception as e:
                    if not result.get("error"):
                        result["error"] = f"pyOpenSSL close warning: {e}"
            raw.close()
        except Exception as e:
            result["error"] = str(e)

        # Second pass: confirm enforcement
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw2:
                with ctx2.wrap_socket(raw2, server_hostname=host):
                    pass  # succeeded -- mTLS requested but NOT enforced
        except ssl.SSLError as e:
            msg = str(e).lower()
            result["_without_cert_handshake_failed"] = True
            certificate_alert = any(
                marker in msg
                for marker in (
                    "certificate required",
                    "bad certificate",
                    "peer did not return a certificate",
                )
            )
            if certificate_alert or result["mtls_requested"]:
                result["mtls_enforced"] = True
                result["mtls_requested"] = True
        except Exception as e:
            if not result.get("error"):
                result["error"] = f"mTLS enforcement check warning: {e}"

    # -----------------------------------------------------------------------
    # Step 2: Parse openssl -msg for CA names and sig algs
    # -----------------------------------------------------------------------
    cas, algs, openssl_ok = _run_openssl_msg(host, port, timeout=max(10, int(timeout) + 5))
    if openssl_ok:
        result["acceptable_cas"] = cas
        result["requested_sig_algs"] = algs
        # If openssl found CA names, we know mTLS was requested even if
        # pyOpenSSL callback missed it (e.g. TLS 1.3)
        if cas or algs:
            result["mtls_requested"] = True

    if result.get("mtls_requested") and result.get("_without_cert_handshake_failed"):
        result["mtls_enforced"] = True
    result.pop("_without_cert_handshake_failed", None)

    if result["mtls_requested"] and not result["mtls_enforced"]:
        enforced, evidence, probe_error = _probe_mtls_application_enforcement(
            host, port, timeout
        )
        result["enforcement_evidence"] = evidence
        if enforced:
            result["mtls_enforced"] = True
        elif probe_error and not result.get("error"):
            result["error"] = probe_error

    # -----------------------------------------------------------------------
    # Step 3: Derive enforcement mode, proxy impact, and recommendation
    # -----------------------------------------------------------------------
    if result["mtls_enforced"]:
        result["enforcement_mode"] = "enforced"
        result["inspection_impact"] = (
            "CANNOT INSPECT -- an intercepting proxy does not have the client "
            "private key required by this server."
        )
        result["recommendation"] = (
            "Configure an SSL inspection bypass unless the proxy has an approved "
            "mTLS integration for this application."
        )
    elif result["mtls_requested"]:
        result["enforcement_mode"] = "requested_not_enforced"
        result["inspection_impact"] = (
            "PARTIAL RISK -- Server requests a client cert but does not enforce it. "
            "Token/API-key traffic inspects fine; mTLS-authenticated "
            "service-to-service traffic will fail under inspection."
        )
        result["recommendation"] = (
            "Monitor for client-cert authentication failures. If any service "
            "uses mTLS to this endpoint, add to SSL Bypass list."
        )
    else:
        result["enforcement_mode"] = "none"
        result["inspection_impact"] = "No mTLS requirement was detected."
        result["recommendation"] = "No action required."

    return result


# ---------------------------------------------------------------------------
# Core TLS functions
# ---------------------------------------------------------------------------

def _sni_bytes(host: str) -> Optional[bytes]:
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host.encode("idna")


def _format_openssl_error(error: Exception) -> str:
    details = error.args[0] if error.args else str(error)
    if isinstance(details, list):
        messages = []
        for item in details:
            if isinstance(item, tuple):
                messages.append(": ".join(str(part) for part in item if part))
            else:
                messages.append(str(item))
        return "; ".join(messages) or error.__class__.__name__
    return str(details)


def _do_openssl_handshake(connection, raw_socket, timeout: float) -> None:
    """Complete a pyOpenSSL handshake with a real deadline."""
    deadline = time.monotonic() + timeout
    raw_socket.setblocking(False)
    while True:
        try:
            connection.do_handshake()
            return
        except SSL.WantReadError:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([raw_socket], [], [], remaining)[0]:
                raise TimeoutError("TLS handshake timed out")
        except SSL.WantWriteError:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [raw_socket], [], remaining)[1]:
                raise TimeoutError("TLS handshake timed out")


def _stdlib_tls_handshake(
    host: str,
    port: int,
    timeout: float,
    verify: bool,
    certfile: Optional[str],
    keyfile: Optional[str],
) -> dict:
    if verify:
        context = ssl.create_default_context()
        context.check_hostname = False
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    context.set_alpn_protocols(["h2", "http/1.1"])
    if certfile and keyfile:
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            cipher = tls_socket.cipher()
            chain_method = getattr(tls_socket, "get_unverified_chain", None)
            chain_der = list(chain_method()) if chain_method is not None else []
            leaf_der = tls_socket.getpeercert(binary_form=True)
            if leaf_der and not chain_der:
                chain_der = [leaf_der]
            return {
                "tls_version": tls_socket.version(),
                "cipher": {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2],
                },
                "chain_der": chain_der,
                "handshake": {
                    "compression": tls_socket.compression(),
                    "alpn": tls_socket.selected_alpn_protocol(),
                    "session_reused": tls_socket.session_reused,
                    "secure_renegotiation": None,
                    "ephemeral_key": None,
                },
            }


def _inspect_peer_with_pyopenssl(
    host: str,
    port: int,
    timeout: float,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
) -> dict:
    """Collect an unverified chain and a stapled OCSP response."""
    unavailable = {
        "chain_der": [],
        "ocsp_stapling": {
            "status": "unavailable",
            "response_status": None,
            "certificate_status": None,
        },
    }
    if not HAS_PYOPENSSL:
        return unavailable

    raw_socket = None
    connection = None
    ocsp_state = {"response": None}

    def ocsp_callback(_connection, response, _data):
        ocsp_state["response"] = bytes(response) if response else None
        return True

    try:
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
        context.set_ocsp_client_callback(ocsp_callback)
        if certfile and keyfile:
            context.use_certificate_chain_file(certfile)
            context.use_privatekey_file(keyfile)
            context.check_privatekey()

        raw_socket = socket.create_connection((host, port), timeout=timeout)
        connection = SSL.Connection(context, raw_socket)
        server_name = _sni_bytes(host)
        if server_name:
            connection.set_tlsext_host_name(server_name)
        connection.set_connect_state()
        connection.request_ocsp()
        _do_openssl_handshake(connection, raw_socket, timeout)
        chain = connection.get_peer_cert_chain() or []
        chain_der = [
            certificate.to_cryptography().public_bytes(Encoding.DER)
            for certificate in chain
        ]
        return {
            "chain_der": chain_der,
            "ocsp_stapling": parse_ocsp_response(ocsp_state["response"]),
        }
    except (socket.timeout, TimeoutError) as error:
        return {
            "chain_der": [],
            "ocsp_stapling": {
                "status": "error",
                "response_status": None,
                "certificate_status": None,
                "error": f"OCSP probe timed out: {error}",
            },
        }
    except Exception as error:
        return {
            "chain_der": [],
            "ocsp_stapling": {
                "status": "error",
                "response_status": None,
                "certificate_status": None,
                "error": _format_openssl_error(error),
            },
        }
    finally:
        if connection is not None:
            with suppress(Exception):
                connection.close()
        if raw_socket is not None:
            try:
                raw_socket.close()
            except OSError:
                pass


def main_tls_connect(host: str, port: int, timeout: float,
                     certfile: Optional[str] = None,
                     keyfile: Optional[str] = None) -> dict:
    """
    Perform the primary TLS handshake and extract all relevant info.
    Optionally loads a client certificate chain when certfile/keyfile are given.
    Returns verified and diagnostic handshake evidence without hiding bad certs.
    """
    result = {
        "ip": None,
        "tls_version": None,
        "cipher": None,
        "cert": None,
        "handshake": {
            "compression": None,
            "alpn": None,
            "session_reused": False,
            "secure_renegotiation": None,
            "ephemeral_key": None,
        },
        "error": None,
    }
    try:
        ip = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0][4][0]
        result["ip"] = ip
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
        return result

    trust = {"valid": None, "verify_code": None, "error": None}
    handshake = None
    try:
        handshake = _stdlib_tls_handshake(
            host, port, timeout, True, certfile, keyfile
        )
        trust["valid"] = True
    except ssl.SSLCertVerificationError as e:
        trust.update(
            {
                "valid": False,
                "verify_code": getattr(e, "verify_code", None),
                "error": getattr(e, "verify_message", None) or str(e),
            }
        )
    except (ssl.SSLError, OSError, ValueError) as e:
        trust["error"] = str(e)

    if handshake is None:
        try:
            handshake = _stdlib_tls_handshake(
                host, port, timeout, False, certfile, keyfile
            )
        except socket.timeout:
            result["error"] = "Connection timed out"
            return result
        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}"
            return result
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {e}"
            return result
        except OSError as e:
            result["error"] = f"Network error: {e}"
            return result
        except ValueError as e:
            result["error"] = f"TLS configuration error: {e}"
            return result

    result["tls_version"] = handshake["tls_version"]
    result["cipher"] = handshake["cipher"]
    result["handshake"] = handshake["handshake"]

    peer_inspection = _inspect_peer_with_pyopenssl(
        host, port, timeout, certfile=certfile, keyfile=keyfile
    )
    chain_der = handshake["chain_der"] or peer_inspection["chain_der"]
    try:
        result["cert"] = parse_certificate_chain(
            chain_der,
            host,
            trust,
            ocsp_stapling=peer_inspection["ocsp_stapling"],
        )
    except (ValueError, TypeError) as error:
        result["handshake"]["certificate_parse_error"] = str(error)
    return result


PROTOCOL_PROFILES = (
    ("SSLv2", None),
    ("SSLv3", "SSL3_VERSION"),
    ("TLSv1.0", "TLS1_VERSION"),
    ("TLSv1.1", "TLS1_1_VERSION"),
    ("TLSv1.2", "TLS1_2_VERSION"),
    ("TLSv1.3", "TLS1_3_VERSION"),
)


def _openssl_exact_probe(
    host: str,
    port: int,
    timeout: float,
    protocol_name: str,
    protocol_attribute: Optional[str],
    cipher_name: Optional[str] = None,
) -> dict:
    """Perform one exact protocol/cipher handshake with pyOpenSSL."""
    base = {
        "status": "local_unsupported",
        "accepted": False,
        "negotiated_protocol": None,
        "negotiated_cipher": None,
        "bits": None,
        "error": None,
        "probe_engine": "pyopenssl" if HAS_PYOPENSSL else "unavailable",
    }
    if not HAS_PYOPENSSL:
        base["error"] = "pyOpenSSL is unavailable"
        return base
    if protocol_attribute is None or not hasattr(SSL, protocol_attribute):
        base["error"] = f"{protocol_name} is not supported by the local TLS backend"
        return base

    protocol_version = getattr(SSL, protocol_attribute)
    try:
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
        context.set_min_proto_version(protocol_version)
        context.set_max_proto_version(protocol_version)
        if protocol_name == "TLSv1.3":
            if cipher_name:
                context.set_tls13_ciphersuites(cipher_name.encode("ascii"))
        else:
            cipher_expression = (
                f"{cipher_name}:@SECLEVEL=0" if cipher_name else "ALL:@SECLEVEL=0"
            )
            context.set_cipher_list(cipher_expression.encode("ascii"))
    except Exception as error:
        base["error"] = _format_openssl_error(error)
        return base

    raw_socket = None
    connection = None
    try:
        raw_socket = socket.create_connection((host, port), timeout=timeout)
        connection = SSL.Connection(context, raw_socket)
        server_name = _sni_bytes(host)
        if server_name:
            connection.set_tlsext_host_name(server_name)
        connection.set_connect_state()
        _do_openssl_handshake(connection, raw_socket, timeout)
        negotiated_protocol = connection.get_protocol_version_name()
        negotiated_cipher = connection.get_cipher_name()
        bits = connection.get_cipher_bits()
        if cipher_name and negotiated_cipher != cipher_name:
            base.update(
                {
                    "status": "error",
                    "negotiated_protocol": negotiated_protocol,
                    "negotiated_cipher": negotiated_cipher,
                    "bits": bits,
                    "error": (
                        f"requested {cipher_name}, but negotiated {negotiated_cipher}"
                    ),
                }
            )
            return base
        base.update(
            {
                "status": "accepted",
                "accepted": True,
                "negotiated_protocol": negotiated_protocol,
                "negotiated_cipher": negotiated_cipher,
                "bits": bits,
            }
        )
        return base
    except (socket.timeout, TimeoutError) as error:
        base.update({"status": "error", "error": f"probe timed out: {error}"})
        return base
    except SSL.Error as error:
        message = _format_openssl_error(error)
        local_errors = (
            "no protocols available",
            "no ciphers available",
            "unsupported protocol",
            "no cipher match",
        )
        status = (
            "local_unsupported"
            if any(token in message.lower() for token in local_errors)
            else "rejected"
        )
        base.update({"status": status, "error": message})
        return base
    except OSError as error:
        base.update({"status": "error", "error": str(error)})
        return base
    finally:
        if connection is not None:
            with suppress(Exception):
                connection.close()
        if raw_socket is not None:
            try:
                raw_socket.close()
            except OSError:
                pass


def probe_protocols(host: str, port: int, timeout: float) -> list[dict]:
    """Probe each SSL/TLS protocol version independently."""
    results = []
    for name, attribute in PROTOCOL_PROFILES:
        result = _openssl_exact_probe(host, port, timeout, name, attribute)
        result["name"] = name
        results.append(result)
    return results


def probe_inspection_profile(
    host: str,
    port: int,
    timeout: float,
    profile: InspectionProfile,
) -> dict:
    """Offer only profile suites and report the negotiated overlap."""
    result = {
        "status": "local_unsupported",
        "accepted": False,
        "negotiated_protocol": None,
        "negotiated_cipher": None,
        "cipher_status": None,
        "bits": None,
        "error": None,
        "probe_engine": "pyopenssl" if HAS_PYOPENSSL else "unavailable",
        "profile_id": profile.id,
        "candidate_count": len(profile.supported_ciphers),
    }
    if not HAS_PYOPENSSL:
        result["error"] = "pyOpenSSL is unavailable"
        return result

    required_attributes = (
        "TLS1_VERSION",
        "TLS1_3_VERSION",
    )
    if any(not hasattr(SSL, attribute) for attribute in required_attributes):
        result["error"] = "local TLS backend cannot probe the full TLS 1.0-1.3 range"
        return result
    if not hasattr(SSL.Context, "set_tls13_ciphersuites"):
        result["error"] = "local TLS backend cannot constrain TLS 1.3 cipher suites"
        return result

    tls12_candidates = sorted(profile.supported_ciphers - profile.tls13_pfs)
    tls13_candidates = sorted(profile.tls13_pfs)
    try:
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_verify(SSL.VERIFY_NONE, lambda *_args: True)
        context.set_min_proto_version(SSL.TLS1_VERSION)
        context.set_max_proto_version(SSL.TLS1_3_VERSION)
        context.set_cipher_list(
            (":".join(tls12_candidates) + ":@SECLEVEL=0").encode("ascii")
        )
        context.set_tls13_ciphersuites(":".join(tls13_candidates).encode("ascii"))
    except Exception as error:
        result["error"] = _format_openssl_error(error)
        return result

    raw_socket = None
    connection = None
    try:
        raw_socket = socket.create_connection((host, port), timeout=timeout)
        connection = SSL.Connection(context, raw_socket)
        server_name = _sni_bytes(host)
        if server_name:
            connection.set_tlsext_host_name(server_name)
        connection.set_connect_state()
        _do_openssl_handshake(connection, raw_socket, timeout)
        negotiated_cipher = connection.get_cipher_name()
        negotiated_protocol = connection.get_protocol_version_name()
        if negotiated_cipher not in profile.supported_ciphers:
            result.update(
                {
                    "status": "error",
                    "negotiated_protocol": negotiated_protocol,
                    "negotiated_cipher": negotiated_cipher,
                    "bits": connection.get_cipher_bits(),
                    "error": "probe negotiated a cipher outside the offered profile",
                }
            )
            return result
        result.update(
            {
                "status": "accepted",
                "accepted": True,
                "negotiated_protocol": negotiated_protocol,
                "negotiated_cipher": negotiated_cipher,
                "cipher_status": cipher_profile_status(negotiated_cipher, profile),
                "bits": connection.get_cipher_bits(),
            }
        )
        return result
    except (socket.timeout, TimeoutError) as error:
        result.update({"status": "error", "error": f"probe timed out: {error}"})
        return result
    except SSL.Error as error:
        result.update({"status": "rejected", "error": _format_openssl_error(error)})
        return result
    except OSError as error:
        result.update({"status": "error", "error": str(error)})
        return result
    finally:
        if connection is not None:
            with suppress(Exception):
                connection.close()
        if raw_socket is not None:
            with suppress(OSError):
                raw_socket.close()


def probe_ephemeral_key(
    host: str,
    port: int,
    timeout: float,
    cipher_name: str,
) -> dict:
    """Use OpenSSL CLI evidence to report a TLS 1.2 ephemeral key."""
    result = {
        "status": "unavailable",
        "type": None,
        "name": None,
        "bits": None,
        "details": None,
        "error": None,
        "probe_engine": "openssl-cli",
    }
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        result["error"] = "openssl command is unavailable"
        return result

    command = [
        openssl_path,
        "s_client",
        "-connect",
        format_host_port(host, port),
        "-tls1_2",
        "-cipher",
        f"{cipher_name}:@SECLEVEL=0",
        "-brief",
    ]
    server_name = _sni_bytes(host)
    if server_name:
        command.extend(["-servername", host])
    try:
        completed = subprocess.run(
            command,
            input=b"",
            capture_output=True,
            timeout=max(2, int(timeout) + 1),
        )  # nosec B603
    except subprocess.TimeoutExpired:
        result.update({"status": "error", "error": "ephemeral-key probe timed out"})
        return result
    except OSError as error:
        result.update({"status": "error", "error": str(error)})
        return result

    output = (completed.stdout + completed.stderr).decode(errors="replace")
    match = re.search(
        r"(?:Peer|Server) Temp Key:\s*([^,\r\n]+)(?:,\s*(\d+)\s*bits)?",
        output,
        flags=re.IGNORECASE,
    )
    if match:
        key_name = match.group(1).strip()
        result.update(
            {
                "status": "observed",
                "type": "DH" if key_name.upper() == "DH" else "EC",
                "name": key_name,
                "bits": int(match.group(2)) if match.group(2) else None,
                "details": match.group(0).strip(),
            }
        )
        return result

    error_lines = [
        line.strip()
        for line in output.splitlines()
        if "error:" in line.lower() or "dh key" in line.lower()
    ]
    result.update(
        {
            "status": "rejected" if completed.returncode else "not_observed",
            "error": "; ".join(error_lines[-3:]) or None,
        }
    )
    return result


def _cipher_probe_profiles(cipher_name: str, declared_protocol: str) -> list[tuple[str, str]]:
    if cipher_name.startswith("TLS_"):
        return [("TLSv1.3", "TLS1_3_VERSION")]

    profiles = [("TLSv1.2", "TLS1_2_VERSION")]
    legacy_cipher = (
        declared_protocol in {"SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
        or (
            cipher_name.endswith("-SHA")
            and not any(token in cipher_name for token in ("GCM", "CCM", "CHACHA"))
        )
    )
    if legacy_cipher:
        profiles.extend(
            [
                ("TLSv1.1", "TLS1_1_VERSION"),
                ("TLSv1.0", "TLS1_VERSION"),
            ]
        )
    return profiles


def probe_cipher(
    host: str,
    port: int,
    timeout: float,
    cipher_name: str,
    declared_protocol: str = "TLSv1.2",
) -> dict:
    """Probe a cipher exactly and verify the negotiated suite."""
    attempts = []
    for protocol_name, protocol_attribute in _cipher_probe_profiles(
        cipher_name, declared_protocol
    ):
        result = _openssl_exact_probe(
            host,
            port,
            timeout,
            protocol_name,
            protocol_attribute,
            cipher_name=cipher_name,
        )
        attempts.append({"protocol": protocol_name, **result})

    accepted = [attempt for attempt in attempts if attempt["status"] == "accepted"]
    statuses = {attempt["status"] for attempt in attempts}
    if accepted:
        status = "accepted"
    elif statuses == {"local_unsupported"}:
        status = "local_unsupported"
    elif "rejected" in statuses:
        status = "rejected"
    else:
        status = "error"

    errors = [
        f"{attempt['protocol']}: {attempt['error']}"
        for attempt in attempts
        if attempt.get("error")
    ]
    return {
        "status": status,
        "accepted": bool(accepted),
        "accepted_protocols": [
            attempt["negotiated_protocol"] for attempt in accepted
        ],
        "negotiated_cipher": (
            accepted[0]["negotiated_cipher"] if accepted else None
        ),
        "bits": accepted[0]["bits"] if accepted else None,
        "error": "; ".join(errors) if errors else None,
        "probe_engine": "pyopenssl" if HAS_PYOPENSSL else "unavailable",
        "attempts": attempts,
    }


def _infer_cipher_bits(cipher_name: str) -> int:
    if "AES256" in cipher_name or "CHACHA20" in cipher_name:
        return 256
    if "AES128" in cipher_name:
        return 128
    return 0


def _cipher_inventory(profile: InspectionProfile) -> list[dict]:
    """Return modern local ciphers plus the selected profile's full set."""
    inventory = {
        item["name"]: item for item in ssl.create_default_context().get_ciphers()
    }
    legacy_expression = ":".join(
        sorted(profile.ecdhe_pfs | profile.dhe_pfs | profile.rsa_no_pfs)
    )
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_ciphers(legacy_expression + ":@SECLEVEL=0")
        for item in context.get_ciphers():
            if item["name"] in profile.supported_ciphers:
                inventory[item["name"]] = item
    except ssl.SSLError:
        pass

    try:
        weak_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        weak_context.set_ciphers("eNULL:aNULL:@SECLEVEL=0")
        for item in weak_context.get_ciphers():
            if item["name"] in WEAK_CIPHER_CANDIDATES:
                inventory[item["name"]] = item
    except ssl.SSLError:
        pass

    for name in profile.supported_ciphers | WEAK_CIPHER_CANDIDATES:
        if name in inventory:
            continue
        if name in profile.tls13_pfs:
            protocol = "TLSv1.3"
        elif any(token in name for token in ("GCM", "SHA256", "SHA384")):
            protocol = "TLSv1.2"
        else:
            protocol = "TLSv1.0"
        inventory[name] = {
            "name": name,
            "protocol": protocol,
            "bits": _infer_cipher_bits(name),
        }
    return sorted(inventory.values(), key=lambda item: (item.get("protocol", ""), item["name"]))


def enumerate_ciphers(
    host: str,
    port: int,
    timeout: float,
    profile: InspectionProfile,
    console=None,
) -> list:
    """
    Iterate through the platform's available cipher list, probing each one.
    Returns list of dicts with: name, protocol, bits, accepted, profile_status.
    """
    available = _cipher_inventory(profile)
    results = []

    def run_probe(cipher: dict) -> dict:
        name = cipher["name"]
        probe = probe_cipher(
            host,
            port,
            timeout,
            name,
            declared_protocol=cipher.get("protocol", ""),
        )
        result = {
            "name": name,
            "protocol": cipher.get("protocol", ""),
            "profile_status": cipher_profile_status(name, profile),
            **probe,
        }
        if result.get("bits") is None:
            result["bits"] = cipher.get(
                "strength_bits", cipher.get("bits", _infer_cipher_bits(name))
            )
        return result

    if RICH_AVAILABLE and console:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Probing ciphers...", total=len(available))
            for c in available:
                results.append(run_probe(c))
                progress.advance(task)
    else:
        for i, c in enumerate(available):
            result = run_probe(c)
            results.append(result)
            if not RICH_AVAILABLE:
                print(
                    f"  [{i+1}/{len(available)}] {c['name']}: {result['status']}",
                    end="\r",
                )
        if not RICH_AVAILABLE:
            print()
    return results


def inspection_verdict(cipher_name: str, profile: InspectionProfile) -> tuple:
    """Return (verdict_key, label, color) for the negotiated cipher."""
    status = cipher_profile_status(cipher_name, profile)
    if status == "supported_pfs":
        return ("can_inspect", "CAN INSPECT", "green")
    elif status == "no_pfs":
        return ("partial_no_pfs", "PARTIAL - NO PFS", "yellow")
    elif status == "ecdsa_server_only":
        return ("server_side_only", "SERVER-SIDE ONLY", "blue")
    else:
        return ("cannot_inspect", "CANNOT INSPECT", "red")


def assess_inspection_compatibility(
    conn: dict,
    profile: InspectionProfile,
    enum_results: Optional[list] = None,
    mtls: Optional[dict] = None,
    compatibility_probe: Optional[dict] = None,
) -> dict:
    """Build the endpoint-side security-proxy inspection assessment."""
    enum_results = enum_results or []
    compatibility_probe = compatibility_probe or None
    profile_metadata = profile.as_dict()
    compatible_statuses = {"supported_pfs", "no_pfs", "ecdsa_server_only"}
    baseline_cipher = (conn.get("cipher") or {}).get("name")
    baseline_status = (
        cipher_profile_status(baseline_cipher, profile) if baseline_cipher else None
    )
    accepted_results = [
        item
        for item in enum_results
        if item.get("status") == "accepted" or item.get("accepted") is True
    ]
    compatible_results = [
        item
        for item in accepted_results
        if cipher_profile_status(item.get("name", ""), profile)
        in compatible_statuses
    ]
    evidence = {
        "baseline_cipher": baseline_cipher,
        "baseline_cipher_status": baseline_status,
        "compatible_cipher": None,
        "compatible_cipher_status": None,
        "accepted_compatible_ciphers": sorted(
            {item["name"] for item in compatible_results}
        ),
        "accepted_incompatible_ciphers": sorted(
            {
                item["name"]
                for item in accepted_results
                if cipher_profile_status(item.get("name", ""), profile)
                == "not_supported"
            }
        ),
        "compatibility_probe": compatibility_probe,
        "mtls_enforced": bool(mtls and mtls.get("mtls_enforced")),
        "profile_id": profile.id,
    }
    limitations = [
        "Endpoint TLS compatibility does not evaluate proxy policy or bypass rules.",
        "Application certificate pinning cannot be inferred from a remote TLS handshake.",
    ]

    if mtls and mtls.get("mtls_enforced"):
        return {
            "profile": profile_metadata,
            "key": "cannot_inspect",
            "label": "TLS INSPECTION NOT COMPATIBLE",
            "inspectable": False,
            "confidence": "high",
            "reason_code": "mtls_enforced",
            "summary": "The endpoint enforces a client certificate, which breaks ordinary proxy TLS interception.",
            "recommendation": "Use an SSL-inspection bypass unless the proxy has an approved mTLS integration for this application.",
            "evidence": evidence,
            "limitations": limitations,
        }

    proof_cipher = None
    proof_status = None
    proof_source = None
    if compatible_results:
        proof_cipher = compatible_results[0]["name"]
        proof_status = cipher_profile_status(proof_cipher, profile)
        proof_source = "exact_cipher_enumeration"
    elif compatibility_probe and compatibility_probe.get("status") == "accepted":
        proof_cipher = compatibility_probe.get("negotiated_cipher")
        proof_status = cipher_profile_status(proof_cipher or "", profile)
        proof_source = "profile_overlap_probe"
    elif baseline_status in compatible_statuses:
        proof_cipher = baseline_cipher
        proof_status = baseline_status
        proof_source = "baseline_negotiation"

    if proof_cipher and proof_status in compatible_statuses:
        evidence["compatible_cipher"] = proof_cipher
        evidence["compatible_cipher_status"] = proof_status
        if proof_status == "no_pfs":
            key = "partial_no_pfs"
            summary = (
                "A documented profile-compatible RSA cipher overlap was proven, "
                "but the selected suite does not provide Perfect Forward Secrecy."
            )
        elif proof_status == "ecdsa_server_only":
            key = "server_side_only"
            summary = (
                "A documented ECDSA cipher overlap was proven for the "
                "proxy-to-server TLS connection."
            )
        else:
            key = "can_inspect"
            summary = (
                "A documented profile-compatible cipher overlap with Perfect "
                "Forward Secrecy was proven."
            )
        if mtls and mtls.get("mtls_requested"):
            summary += " The server requested, but did not enforce, a client certificate."
        return {
            "profile": profile_metadata,
            "key": key,
            "label": "TLS INSPECTION COMPATIBLE",
            "inspectable": True,
            "confidence": "high",
            "reason_code": "supported_cipher_overlap",
            "proof_source": proof_source,
            "summary": summary,
            "recommendation": "No endpoint TLS compatibility bypass is indicated.",
            "evidence": evidence,
            "limitations": limitations,
        }

    candidate_results = [
        item
        for item in enum_results
        if item.get("name") in profile.supported_ciphers
    ]
    candidate_names = {item.get("name") for item in candidate_results}
    full_negative_proof = (
        candidate_names == profile.supported_ciphers
        and all(item.get("status") == "rejected" for item in candidate_results)
    )
    quick_negative_proof = bool(
        compatibility_probe and compatibility_probe.get("status") == "rejected"
    )
    if full_negative_proof or quick_negative_proof:
        return {
            "profile": profile_metadata,
            "key": "cannot_inspect",
            "label": "TLS INSPECTION NOT COMPATIBLE",
            "inspectable": False,
            "confidence": "high",
            "reason_code": "no_supported_cipher_overlap",
            "summary": "The endpoint rejected an offer containing only cipher suites from the selected inspection profile.",
            "recommendation": "An SSL-inspection bypass is likely required; confirm the proxy policy before deployment.",
            "evidence": evidence,
            "limitations": limitations,
        }

    if conn.get("error"):
        summary = (
            "The endpoint handshake did not complete, so proxy inspection "
            "compatibility could not be established."
        )
    elif compatibility_probe and compatibility_probe.get("error"):
        summary = (
            "The local TLS backend could not complete the targeted compatibility "
            "probe."
        )
    else:
        summary = "No cipher overlap with the selected inspection profile was proven."
    return {
        "profile": profile_metadata,
        "key": "unavailable",
        "label": "TLS INSPECTION INDETERMINATE",
        "inspectable": None,
        "confidence": "low",
        "reason_code": "insufficient_evidence",
        "summary": summary,
        "recommendation": "Run --full and review backend limitations before creating a bypass.",
        "evidence": evidence,
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Rich output rendering
# ---------------------------------------------------------------------------

def render_rich(
    host: str,
    port: int,
    conn: dict,
    enum_results: list,
    mtls: dict,
    protocol_results: list,
    security_assessment: dict,
    inspection_assessment: dict,
    args_timeout: float,
    console: "Console",
):
    """Render all panels using Rich."""

    # -- Panel 1: Connection Summary ----------------------------------------
    if conn["error"]:
        console.print(Panel(
            Text(f"[bold red]ERROR:[/bold red] {conn['error']}"),
            title="[bold red]Baseline Connection Failed",
            border_style="red",
        ))

    cert = conn.get("cert") or {
        "expired": False,
        "expiring_soon": False,
        "cn": "unavailable",
        "issuer_cn": "unavailable",
        "issuer_org": "",
        "not_before": "unavailable",
        "not_after": "unavailable",
        "days_left": 0,
        "sans": [],
    }
    cipher = conn.get("cipher") or {
        "name": "unavailable",
        "protocol": "unavailable",
        "bits": 0,
    }

    if cert["expired"]:
        expiry_style = "bold red"
        expiry_note  = " [EXPIRED]"
    elif cert["expiring_soon"]:
        expiry_style = "bold yellow"
        expiry_note  = " [EXPIRING SOON]"
    else:
        expiry_style = "bold green"
        expiry_note  = ""

    summary_text = Text()
    summary_text.append("  Host        : ", style="bold")
    summary_text.append(f"{host}:{port}\n")
    summary_text.append("  Resolved IP : ", style="bold")
    summary_text.append(f"{conn['ip']}\n")
    summary_text.append("  TLS Version : ", style="bold")
    summary_text.append(f"{conn['tls_version']}\n")
    summary_text.append("  Cipher      : ", style="bold")
    summary_text.append(f"{cipher['name']}  ({cipher['protocol']}, {cipher['bits']} bits)\n\n")
    summary_text.append("  Cert CN     : ", style="bold")
    summary_text.append(f"{cert['cn']}\n")
    summary_text.append("  Issuer      : ", style="bold")
    summary_text.append(f"{cert['issuer_cn']} / {cert['issuer_org']}\n")
    summary_text.append("  Valid From  : ", style="bold")
    summary_text.append(f"{cert['not_before']}\n")
    summary_text.append("  Expires     : ", style="bold")
    summary_text.append(
        f"{cert['not_after']}  ({cert['days_left']} days left){expiry_note}\n",
        style=expiry_style,
    )
    if cert["sans"]:
        summary_text.append("  SANs        : ", style="bold")
        summary_text.append(", ".join(cert["sans"][:6]))
        if len(cert["sans"]) > 6:
            summary_text.append(f" ... +{len(cert['sans'])-6} more")
        summary_text.append("\n")

    public_key = cert.get("public_key") or {}
    if public_key:
        key_text = public_key.get("type", "unknown")
        if public_key.get("bits"):
            key_text += f" {public_key['bits']} bits"
        if public_key.get("curve"):
            key_text += f" ({public_key['curve']})"
        summary_text.append("  Public Key  : ", style="bold")
        summary_text.append(f"{key_text}\n")
    signature = cert.get("signature_algorithm") or {}
    if signature:
        summary_text.append("  Signature   : ", style="bold")
        summary_text.append(f"{signature.get('name', 'unknown')}\n")
    trust = cert.get("trust") or {}
    if trust.get("valid") is not None:
        summary_text.append("  Chain Trust : ", style="bold")
        summary_text.append(
            "VALID\n" if trust["valid"] else "INVALID\n",
            style="green" if trust["valid"] else "bold red",
        )
    if cert.get("hostname_valid") is not None:
        summary_text.append("  Hostname    : ", style="bold")
        summary_text.append(
            "MATCH\n" if cert["hostname_valid"] else "MISMATCH\n",
            style="green" if cert["hostname_valid"] else "bold red",
        )
    handshake = conn.get("handshake") or {}
    summary_text.append("  Compression : ", style="bold")
    summary_text.append(f"{handshake.get('compression') or 'none'}\n")
    summary_text.append("  ALPN        : ", style="bold")
    summary_text.append(f"{handshake.get('alpn') or 'none'}\n")

    all_findings = (security_assessment or {}).get("findings", [])
    certificate_findings = [
        finding for finding in all_findings if finding.get("category") == "certificate"
    ]
    inspectable = inspection_assessment.get("inspectable")
    profile_metadata = inspection_assessment.get("profile", {})
    proxy_style = "bold green" if inspectable is True else "bold red" if inspectable is False else "bold yellow"
    quick_text = Text()
    quick_text.append("  Proxy inspection : ", style="bold")
    quick_text.append(
        f"{inspection_assessment.get('label', 'TLS INSPECTION INDETERMINATE')}\n",
        style=proxy_style,
    )
    quick_text.append("  Profile          : ", style="bold")
    quick_text.append(f"{profile_metadata.get('id', 'unknown')}\n")
    quick_text.append("  Certificate      : ", style="bold")
    if conn.get("cert") is None:
        quick_text.append("UNAVAILABLE\n", style="bold yellow")
    elif certificate_findings:
        quick_text.append(
            f"ISSUES FOUND ({len(certificate_findings)})\n",
            style="bold red",
        )
        quick_text.append(
            "  Main issue       : ",
            style="bold",
        )
        quick_text.append(f"{certificate_findings[0]['title']}\n", style="red")
    else:
        quick_text.append("VALID - no certificate issues detected\n", style="bold green")
    console.print(
        Panel(
            quick_text,
            title="[bold]Troubleshooting Summary",
            border_style=(
                "red"
                if inspectable is False or certificate_findings
                else "yellow" if inspectable is None else "green"
            ),
        )
    )

    console.print(Panel(summary_text, title="[bold cyan]1 - Connection Summary", border_style="cyan"))

    # -- Panel 2: Protocol support -------------------------------------------
    if protocol_results:
        protocol_table = Table(box=box.SIMPLE, show_header=True, header_style="bold white")
        protocol_table.add_column("Protocol", min_width=10)
        protocol_table.add_column("Status", min_width=18)
        protocol_table.add_column("Negotiated Cipher", min_width=34)
        protocol_styles = {
            "accepted": ("ACCEPTED", "green"),
            "rejected": ("REJECTED", "dim"),
            "local_unsupported": ("LOCAL UNAVAILABLE", "yellow"),
            "error": ("ERROR", "red"),
        }
        for item in protocol_results:
            label, style = protocol_styles.get(item["status"], (item["status"], "white"))
            protocol_table.add_row(
                item["name"],
                f"[{style}]{label}[/{style}]",
                item.get("negotiated_cipher") or "-",
            )
        console.print(
            Panel(
                protocol_table,
                title="[bold blue]2 - Protocol Support",
                border_style="blue",
            )
        )
    else:
        console.print(
            Panel(
                Text("Protocol probing skipped (--no-protocols).", style="dim"),
                title="[bold blue]2 - Protocol Support",
                border_style="blue",
            )
        )

    # -- Panel 3: Cipher Enumeration Table ----------------------------------
    if enum_results:
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white",
            title="Cipher Enumeration",
            expand=False,
        )
        table.add_column("Cipher Name",     style="",         min_width=36)
        table.add_column("Protocol",        justify="center", min_width=8)
        table.add_column("Bits",            justify="right",  min_width=5)
        table.add_column("Server Accepts",  justify="center", min_width=14)
        table.add_column("Profile Status", min_width=28)

        STATUS_LABEL = {
            "supported_pfs":     ("OK Supported (PFS)",   "green"),
            "no_pfs":            ("WARN No PFS",           "yellow"),
            "ecdsa_server_only": ("INFO Server-side only", "blue"),
            "not_supported":     ("FAIL Not supported",    "red"),
        }

        for c in sorted(enum_results, key=lambda x: (x["profile_status"], x["name"])):
            status_label, row_style = STATUS_LABEL[c["profile_status"]]
            probe_labels = {
                "accepted": "[green]YES[/green]",
                "rejected": "[red]NO[/red]",
                "local_unsupported": "[yellow]LOCAL N/A[/yellow]",
                "error": "[red]ERROR[/red]",
            }
            accepted_cell = probe_labels.get(c.get("status"), "[dim]UNKNOWN[/dim]")
            table.add_row(
                f"[{row_style}]{c['name']}[/{row_style}]",
                c["protocol"],
                str(c["bits"]),
                accepted_cell,
                f"[{row_style}]{status_label}[/{row_style}]",
            )

        console.print(Panel(table, title="[bold magenta]3 - Cipher Enumeration", border_style="magenta"))
    else:
        console.print(Panel(
            Text(
                "Quick mode checks proxy compatibility without exhaustive cipher "
                "enumeration. Use --full for deep cipher diagnostics.",
                style="dim",
            ),
            title="[bold magenta]3 - Cipher Enumeration",
            border_style="magenta",
        ))

    # -- Panel 4: mTLS / Client Certificate ---------------------------------
    if mtls is not None:
        mode = mtls.get("enforcement_mode", "none")
        # Border colour driven by enforcement mode
        if mode == "enforced":
            border = "red"
            impact_style = "bold red"
            rec_style    = "bold red"
        elif mode == "requested_not_enforced":
            border = "yellow"
            impact_style = "bold yellow"
            rec_style    = "yellow"
        else:
            border = "green"
            impact_style = "green"
            rec_style    = "green"

        mtls_text = Text()
        mtls_text.append("  Detection method  : ", style="bold")
        mtls_text.append(f"{mtls['method']}\n")
        mtls_text.append("  CertificateRequest: ", style="bold")
        if mtls["mtls_requested"]:
            mtls_text.append("YES\n", style="bold yellow")
        else:
            mtls_text.append("No\n", style="green")
        mtls_text.append("  mTLS enforced     : ", style="bold")
        if mtls["mtls_enforced"]:
            mtls_text.append("YES\n", style="bold red")
        else:
            mtls_text.append("No\n", style="green")
        mtls_text.append("  Enforcement mode  : ", style="bold")
        mtls_text.append(f"{mode}\n")
        if mtls.get("enforcement_evidence"):
            mtls_text.append("  Enforcement proof : ", style="bold")
            mtls_text.append(f"{mtls['enforcement_evidence']}\n", style="dim")
        if mtls.get("error"):
            mtls_text.append("  Detection error   : ", style="bold")
            mtls_text.append(f"{mtls['error']}\n", style="dim")

        # Acceptable CA names
        cas = mtls.get("acceptable_cas", [])
        if cas:
            mtls_text.append("\n")
            mtls_text.append("  Acceptable Client CA names:\n", style="bold")
            for ca in cas:
                mtls_text.append(f"    \u2022 {ca}\n", style="cyan")

        # Requested signature algorithms
        algs = mtls.get("requested_sig_algs", [])
        if algs:
            mtls_text.append("\n")
            mtls_text.append("  Requested Signature Algorithms:\n", style="bold")
            mtls_text.append(f"    {', '.join(algs)}\n", style="dim")

        # Proxy impact + recommendation
        mtls_text.append("\n")
        mtls_text.append("  Inspection Impact:\n", style="bold")
        mtls_text.append(f"    {mtls.get('inspection_impact', '')}\n", style=impact_style)
        mtls_text.append("\n")
        mtls_text.append("  Recommendation:\n", style="bold")
        mtls_text.append(f"    {mtls.get('recommendation', '')}\n", style=rec_style)

        console.print(Panel(
            mtls_text,
            title="[bold]4 - mTLS / Client Certificate",
            border_style=border,
        ))
    else:
        console.print(Panel(
            Text("mTLS detection was not run (connection failed).", style="dim"),
            title="[bold]4 - mTLS / Client Certificate",
            border_style="dim",
        ))

    # -- Panel 5: Security findings ------------------------------------------
    findings = (security_assessment or {}).get("findings", [])
    summary = (security_assessment or {}).get("summary", {})
    if findings:
        findings_table = Table(box=box.SIMPLE, show_header=True, header_style="bold white")
        findings_table.add_column("Severity", min_width=9)
        findings_table.add_column("Finding ID", min_width=24)
        findings_table.add_column("Finding", min_width=34)
        severity_styles = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "blue",
        }
        for finding in findings:
            severity = finding["severity"]
            style = severity_styles[severity]
            findings_table.add_row(
                f"[{style}]{severity.upper()}[/{style}]",
                finding["id"],
                finding["title"],
            )
        highest = summary.get("highest_severity") or "info"
        border = "red" if highest in {"critical", "high"} else "yellow"
        console.print(
            Panel(
                findings_table,
                title=f"[bold]5 - Security Findings ({summary.get('total', len(findings))})",
                border_style=border,
            )
        )
    else:
        console.print(
            Panel(
                Text("No issues were detected by the enabled checks.", style="green"),
                title="[bold green]5 - Security Findings",
                border_style="green",
            )
        )

    # -- Panel 6: Inspection Verdict ----------------------------------------
    verdict_label = inspection_assessment.get(
        "label", "TLS INSPECTION INDETERMINATE"
    )
    inspectable = inspection_assessment.get("inspectable")
    verdict_color = "green" if inspectable is True else "red" if inspectable is False else "yellow"

    if enum_results:
        accepted_list = [c for c in enum_results if c["accepted"]]
        profile_compatible = [
            c for c in accepted_list if c["profile_status"] != "not_supported"
        ]
        count_line = (
            f"{len(profile_compatible)}/{len(accepted_list)} server-accepted "
            "ciphers match the selected profile"
        )
    else:
        proof_source = inspection_assessment.get("proof_source")
        if proof_source == "baseline_negotiation":
            count_line = "Compatibility proven by the negotiated cipher."
        elif proof_source == "profile_overlap_probe":
            count_line = "Compatibility proven by a targeted supported-suite offer."
        else:
            count_line = "Targeted compatibility check; use --full for exhaustive counts."

    verdict_body = Text(justify="center")
    verdict_body.append("\n")
    verdict_body.append(f"  {verdict_label}  \n", style=f"bold {verdict_color} on default")
    verdict_body.append("\n")
    evidence = inspection_assessment.get("evidence", {})
    proof_cipher = evidence.get("compatible_cipher") or cipher["name"]
    verdict_body.append(f"  Compatibility cipher: {proof_cipher}\n", style="bold")
    verdict_body.append(
        f"  Confidence: {inspection_assessment.get('confidence', 'unknown').upper()}\n"
    )
    verdict_body.append(
        f"  Profile: {profile_metadata.get('name', profile_metadata.get('id', 'unknown'))}\n"
    )
    verdict_body.append(f"  {count_line}\n\n")
    verdict_body.append(
        f"  {inspection_assessment.get('summary', '')}\n",
        style=verdict_color,
    )
    verdict_body.append(
        f"  Recommendation: {inspection_assessment.get('recommendation', '')}\n",
        style="bold" if inspectable is False else "",
    )

    # mTLS warning line even when not enforced
    if mtls is not None and mtls["mtls_requested"] and not mtls["mtls_enforced"]:
        verdict_body.append(
            "\n  mTLS was requested (but not enforced). "
            "Monitor for client-cert handshake failures.\n",
            style="bold yellow",
        )

    console.print(Panel(
        verdict_body,
        title=f"[bold {verdict_color}]6 - Inspection Verdict",
        border_style=verdict_color,
    ))

    # -- Panel 7: OpenSSL Commands ------------------------------------------
    openssl_text = Text()
    openssl_text.append("# Test TLS versions manually:\n", style="dim")
    openssl_text.append(f"openssl s_client -connect {host}:{port} -tls1_2\n", style="cyan")
    openssl_text.append(f"openssl s_client -connect {host}:{port} -tls1_3\n", style="cyan")
    openssl_text.append("\n# Test specific cipher:\n", style="dim")
    openssl_text.append(
        f"openssl s_client -connect {host}:{port} -cipher 'ECDHE-RSA-AES256-GCM-SHA384'\n",
        style="cyan",
    )
    openssl_text.append(
        f"openssl s_client -connect {host}:{port} -cipher '{cipher['name']}'\n",
        style="cyan",
    )
    openssl_text.append("\n# Show certificate chain:\n", style="dim")
    openssl_text.append(
        f"openssl s_client -connect {host}:{port} -showcerts </dev/null\n",
        style="cyan",
    )
    openssl_text.append("\n# Check certificate dates:\n", style="dim")
    openssl_text.append(
        f"openssl s_client -connect {host}:{port} </dev/null 2>/dev/null "
        f"| openssl x509 -noout -dates\n",
        style="cyan",
    )
    openssl_text.append("\n# Full mTLS analysis (mirrors what this tool does internally):\n", style="dim")
    openssl_text.append(
        f"openssl s_client -connect {host}:{port} -servername {host} -msg\n",
        style="cyan",
    )
    openssl_text.append("\n# Test with client cert (mTLS):\n", style="dim")
    openssl_text.append(
        f"openssl s_client -connect {host}:{port} -cert client.pem -key client.key\n",
        style="cyan",
    )

    console.print(Panel(openssl_text, title="[bold white]7 - Equivalent OpenSSL Commands", border_style="white"))


# ---------------------------------------------------------------------------
# Plain-text fallback output
# ---------------------------------------------------------------------------

def render_plain(
    host: str,
    port: int,
    conn: dict,
    enum_results: list,
    mtls: dict,
    protocol_results: list,
    security_assessment: dict,
    inspection_assessment: dict,
):
    """Plain text output when Rich is not available."""
    print("=" * 60)
    print("TLS PROXY CHECKER")
    print("=" * 60)

    if conn["error"]:
        print(f"ERROR: {conn['error']}")

    cert = conn.get("cert") or {
        "cn": "unavailable",
        "issuer_cn": "unavailable",
        "issuer_org": "",
        "not_before": "unavailable",
        "not_after": "unavailable",
        "days_left": 0,
        "sans": [],
    }
    cipher = conn.get("cipher") or {
        "name": "unavailable",
        "protocol": "unavailable",
        "bits": 0,
    }

    certificate_findings = [
        finding
        for finding in (security_assessment or {}).get("findings", [])
        if finding.get("category") == "certificate"
    ]
    print("\n[Troubleshooting Summary]")
    print(
        "  Proxy inspection : "
        f"{inspection_assessment.get('label', 'TLS INSPECTION INDETERMINATE')}"
    )
    if conn.get("cert") is None:
        print("  Certificate      : UNAVAILABLE")
    elif certificate_findings:
        print(f"  Certificate      : ISSUES FOUND ({len(certificate_findings)})")
        print(f"  Main issue       : {certificate_findings[0]['title']}")
    else:
        print("  Certificate      : VALID - no certificate issues detected")

    print(f"\n[Connection Summary]")
    print(f"  Host        : {host}:{port}")
    print(f"  Resolved IP : {conn['ip']}")
    print(f"  TLS Version : {conn['tls_version']}")
    print(f"  Cipher      : {cipher['name']} ({cipher['protocol']}, {cipher['bits']} bits)")
    print(f"\n  Cert CN     : {cert['cn']}")
    print(f"  Issuer      : {cert['issuer_cn']} / {cert['issuer_org']}")
    print(f"  Valid From  : {cert['not_before']}")
    print(f"  Expires     : {cert['not_after']} ({cert['days_left']} days left)")
    if cert["sans"]:
        print(f"  SANs        : {', '.join(cert['sans'][:6])}")
    if cert.get("public_key"):
        key = cert["public_key"]
        print(f"  Public Key  : {key['type']} {key.get('bits') or ''} {key.get('curve') or ''}".rstrip())
    if cert.get("signature_algorithm"):
        print(f"  Signature   : {cert['signature_algorithm'].get('name', 'unknown')}")
    if cert.get("trust", {}).get("valid") is not None:
        print(f"  Chain Trust : {'VALID' if cert['trust']['valid'] else 'INVALID'}")
    if cert.get("hostname_valid") is not None:
        print(f"  Hostname    : {'MATCH' if cert['hostname_valid'] else 'MISMATCH'}")
    handshake = conn.get("handshake") or {}
    print(f"  Compression : {handshake.get('compression') or 'none'}")
    print(f"  ALPN        : {handshake.get('alpn') or 'none'}")

    if protocol_results:
        print("\n[Protocol Support]")
        for item in protocol_results:
            cipher_name = item.get("negotiated_cipher") or "-"
            print(f"  {item['name']:<9} {item['status']:<18} {cipher_name}")

    if enum_results:
        print(f"\n[Cipher Enumeration]")
        for c in enum_results:
            print(
                f"  {c.get('status', 'unknown'):<17} "
                f"{c['name']:<44} {c['profile_status']}"
            )

    if mtls is not None:
        print(f"\n[mTLS / Client Certificate]  method={mtls['method']}")
        print(f"  CertificateRequest : {'YES' if mtls['mtls_requested'] else 'No'}")
        print(f"  mTLS enforced      : {'YES' if mtls['mtls_enforced'] else 'No'}")
        print(f"  Enforcement mode   : {mtls.get('enforcement_mode', 'none')}")
        if mtls.get("enforcement_evidence"):
            print(f"  Enforcement proof  : {mtls['enforcement_evidence']}")
        if mtls.get("error"):
            print(f"  Detection note     : {mtls['error']}")

        cas = mtls.get("acceptable_cas", [])
        if cas:
            print()
            print("  Acceptable Client CA names:")
            for ca in cas:
                print(f"    - {ca}")

        algs = mtls.get("requested_sig_algs", [])
        if algs:
            print()
            print(f"  Requested Sig Algs : {', '.join(algs)}")

        impact = mtls.get("inspection_impact", "")
        rec    = mtls.get("recommendation", "")
        if impact:
            print()
            print(f"  Inspection Impact : {impact}")
        if rec:
            print(f"  Recommendation     : {rec}")

    findings = (security_assessment or {}).get("findings", [])
    print("\n[Security Findings]")
    if findings:
        for finding in findings:
            print(
                f"  {finding['severity'].upper():<8} "
                f"{finding['id']:<27} {finding['title']}"
            )
    else:
        print("  No issues were detected by the enabled checks.")

    verdict_label = inspection_assessment.get(
        "label", "TLS INSPECTION INDETERMINATE"
    )
    evidence = inspection_assessment.get("evidence", {})
    print(f"\n[Proxy Inspection] {verdict_label}")
    profile_metadata = inspection_assessment.get("profile", {})
    print(f"  Profile          : {profile_metadata.get('id', 'unknown')}")
    print(f"  Compatible       : {inspection_assessment.get('inspectable')}")
    print(f"  Confidence       : {inspection_assessment.get('confidence', 'unknown')}")
    print(f"  Proof cipher     : {evidence.get('compatible_cipher') or '-'}")
    print(f"  Reason           : {inspection_assessment.get('summary', '')}")
    print(f"  Recommendation   : {inspection_assessment.get('recommendation', '')}")
    if mtls is not None and mtls["mtls_requested"] and not mtls["mtls_enforced"]:
        print("  WARNING: mTLS requested (not enforced). Monitor for failures.")

    print(f"\n[OpenSSL Commands]")
    print(f"  openssl s_client -connect {host}:{port} -tls1_2")
    print(f"  openssl s_client -connect {host}:{port} -tls1_3")
    print(f"  openssl s_client -connect {host}:{port} -cipher '{cipher['name']}'")
    print(f"  openssl s_client -connect {host}:{port} -servername {host} -msg")


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def build_json_output(
    host: str,
    port: int,
    conn: dict,
    enum_results: list,
    mtls: dict,
    profile: InspectionProfile,
    protocol_results: Optional[list] = None,
    compatibility_probe: Optional[dict] = None,
    scan_mode: str = "quick",
) -> dict:
    protocol_results = protocol_results or []

    # Build mtls section with all new keys
    mtls_out = None
    if mtls is not None:
        mtls_out = {
            "mtls_requested":    mtls.get("mtls_requested", False),
            "mtls_enforced":     mtls.get("mtls_enforced", False),
            "method":            mtls.get("method", ""),
            "error":             mtls.get("error"),
            "acceptable_cas":    mtls.get("acceptable_cas", []),
            "requested_sig_algs": mtls.get("requested_sig_algs", []),
            "enforcement_evidence": mtls.get("enforcement_evidence"),
            "enforcement_mode":  mtls.get("enforcement_mode", "none"),
            "inspection_impact": mtls.get("inspection_impact", ""),
            "recommendation":    mtls.get("recommendation", ""),
        }

    security_assessment = analyze_security(
        host, conn, protocol_results, enum_results, mtls
    )
    inspection_assessment = assess_inspection_compatibility(
        conn,
        profile,
        enum_results,
        mtls,
        compatibility_probe,
    )
    return {
        "schema_version": 4,
        "scan_mode": scan_mode,
        "inspection_profile": profile.as_dict(),
        "host": host,
        "port": port,
        "ip": conn.get("ip"),
        "tls_version": conn.get("tls_version"),
        "cipher": conn.get("cipher"),
        "handshake": conn.get("handshake"),
        "certificate": conn.get("cert"),
        "mtls": mtls_out,
        "error": conn.get("error"),
        "inspection_verdict": inspection_assessment,
        "protocol_support": protocol_results,
        "cipher_enumeration": enum_results,
        "security_assessment": security_assessment,
    }


def load_targets_from_file(path: str) -> list:
    """Read a target list, ignoring empty lines and comments."""
    targets = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append({"line": line_number, "target": line})
    return targets


def run_check(target: str, args, console=None) -> dict:
    """Run one TLS check and return JSON-serializable output."""
    started = time.monotonic()
    profile = get_inspection_profile(
        getattr(args, "profile", DEFAULT_PROFILE_ID)
    )
    full_scan = bool(
        getattr(args, "full", False) and not getattr(args, "no_enum", False)
    )
    scan_mode = "full" if full_scan else "quick"
    try:
        host, default_port = parse_host(target)
    except ValueError as error:
        host = target.strip() if isinstance(target, str) else str(target)
        port = args.port if args.port is not None else 443
        conn = {
            "ip": None,
            "tls_version": None,
            "cipher": None,
            "cert": None,
            "handshake": {},
            "error": f"Invalid target: {error}",
        }
        output = build_json_output(
            host,
            port,
            conn,
            [],
            None,
            profile,
            [],
            scan_mode=scan_mode,
        )
        output["target"] = target
        output["duration_ms"] = round((time.monotonic() - started) * 1000)
        return output
    port = args.port if args.port is not None else default_port

    if RICH_AVAILABLE and console is not None and not args.json:
        with console.status("[cyan]Connecting and performing TLS handshake...", spinner="dots"):
            conn = main_tls_connect(host, port, args.timeout,
                                    certfile=getattr(args, "cert", None),
                                    keyfile=getattr(args, "key", None))
    else:
        conn = main_tls_connect(host, port, args.timeout,
                                certfile=getattr(args, "cert", None),
                                keyfile=getattr(args, "key", None))

    protocol_results = []
    if not getattr(args, "no_protocols", False) and conn.get("ip"):
        if RICH_AVAILABLE and console is not None and not args.json:
            with console.status("[cyan]Probing protocol versions...", spinner="dots"):
                protocol_results = probe_protocols(host, port, args.timeout)
        else:
            protocol_results = probe_protocols(host, port, args.timeout)

    enum_results = []
    if full_scan and conn.get("ip"):
        if RICH_AVAILABLE and console is not None and not args.json:
            console.print()
        enum_results = enumerate_ciphers(
            host,
            port,
            args.timeout,
            profile,
            console=console if console is not None and not args.json else None,
        )

    if protocol_results and enum_results:
        protocol_by_name = {item["name"]: item for item in protocol_results}
        protocol_aliases = {"TLSv1": "TLSv1.0"}
        for cipher_result in enum_results:
            if cipher_result.get("status") != "accepted":
                continue
            for protocol_name in cipher_result.get("accepted_protocols", []):
                protocol_name = protocol_aliases.get(protocol_name, protocol_name)
                protocol_result = protocol_by_name.get(protocol_name)
                if protocol_result is not None and protocol_result["status"] != "accepted":
                    protocol_result.update(
                        {
                            "status": "accepted",
                            "accepted": True,
                            "negotiated_protocol": protocol_name,
                            "negotiated_cipher": cipher_result["name"],
                            "bits": cipher_result.get("bits"),
                            "error": None,
                            "probe_engine": "exact-cipher-fallback",
                        }
                    )

    baseline_cipher = (conn.get("cipher") or {}).get("name")
    accepted_compatible = any(
        item.get("status") == "accepted"
        and cipher_profile_status(item.get("name", ""), profile)
        != "not_supported"
        for item in enum_results
    )
    compatibility_probe = None
    if (
        conn.get("ip")
        and not accepted_compatible
        and cipher_profile_status(baseline_cipher or "", profile)
        == "not_supported"
    ):
        if RICH_AVAILABLE and console is not None and not args.json:
            with console.status(
                "[cyan]Checking security-proxy cipher compatibility...",
                spinner="dots",
            ):
                compatibility_probe = probe_inspection_profile(
                    host, port, args.timeout, profile
                )
        else:
            compatibility_probe = probe_inspection_profile(
                host, port, args.timeout, profile
            )

    accepted_dhe = next(
        (
            item
            for item in enum_results
            if item.get("status") == "accepted" and item["name"].startswith("DHE-")
        ),
        None,
    )
    if accepted_dhe:
        ephemeral_probe = probe_ephemeral_key(
            host, port, args.timeout, accepted_dhe["name"]
        )
        conn.setdefault("handshake", {})["ephemeral_key_probe"] = ephemeral_probe
        if ephemeral_probe["status"] == "observed":
            conn["handshake"]["ephemeral_key"] = {
                key: ephemeral_probe[key]
                for key in ("type", "name", "bits", "details")
            }

    mtls = None
    if not conn.get("error") or conn.get("ip"):
        if RICH_AVAILABLE and console is not None and not args.json:
            with console.status("[cyan]Detecting mTLS requirements...", spinner="dots"):
                mtls = detect_mtls(host, port, args.timeout)
        else:
            mtls = detect_mtls(host, port, args.timeout)

    output = build_json_output(
        host,
        port,
        conn,
        enum_results,
        mtls,
        profile,
        protocol_results=protocol_results,
        compatibility_probe=compatibility_probe,
        scan_mode=scan_mode,
    )
    output["target"] = target
    output["duration_ms"] = round((time.monotonic() - started) * 1000)
    return output


def build_batch_output(args) -> dict:
    """Run checks for an input file and return one combined JSON document."""
    started_at = datetime.datetime.now(datetime.timezone.utc)
    targets = load_targets_from_file(args.input_file)
    results = []

    for item in targets:
        result = run_check(item["target"], args, console=None)
        result["line"] = item["line"]
        results.append(result)

    finished_at = datetime.datetime.now(datetime.timezone.utc)
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for result in results:
        counts = (
            result.get("security_assessment", {})
            .get("summary", {})
            .get("counts", {})
        )
        for severity in severity_counts:
            severity_counts[severity] += counts.get(severity, 0)
    highest_severity = next(
        (severity for severity, count in severity_counts.items() if count), None
    )
    inspection_counts = {
        "compatible": sum(
            result.get("inspection_verdict", {}).get("inspectable") is True
            for result in results
        ),
        "not_compatible": sum(
            result.get("inspection_verdict", {}).get("inspectable") is False
            for result in results
        ),
        "indeterminate": sum(
            result.get("inspection_verdict", {}).get("inspectable") is None
            for result in results
        ),
    }
    profile = get_inspection_profile(
        getattr(args, "profile", DEFAULT_PROFILE_ID)
    )
    return {
        "schema_version": 4,
        "tool": "tls-proxy-checker",
        "version": __version__,
        "inspection_profile": profile.as_dict(),
        "scan_mode": (
            "full"
            if getattr(args, "full", False) and not getattr(args, "no_enum", False)
            else "quick"
        ),
        "input_file": args.input_file,
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "finished_at": finished_at.isoformat().replace("+00:00", "Z"),
        "target_count": len(targets),
        "summary": {
            "successful_targets": sum(not result.get("error") for result in results),
            "failed_targets": sum(bool(result.get("error")) for result in results),
            "highest_severity": highest_severity,
            "finding_counts": severity_counts,
            "inspection_compatibility": inspection_counts,
        },
        "results": results,
    }


def emit_json(output: dict, output_file: Optional[str] = None) -> None:
    """Write JSON to stdout or to a file."""
    text = json.dumps(output, indent=2, default=str)
    if output_file:
        output_path = os.path.abspath(output_file)
        output_dir = os.path.dirname(output_path)
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=output_dir,
                prefix=f".{os.path.basename(output_path)}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_path = handle.name
                handle.write(text)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, output_path)
        finally:
            if temporary_path and os.path.exists(temporary_path):
                os.unlink(temporary_path)
        return
    print(text)


def validate_cli_paths(parser: argparse.ArgumentParser, args) -> None:
    """Fail with clean CLI errors for unreadable input or unwritable output."""
    if getattr(args, "port", None) is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if getattr(args, "timeout", 5.0) <= 0:
        parser.error("--timeout must be greater than zero")
    if getattr(args, "full", False) and getattr(args, "no_enum", False):
        parser.error("--full cannot be used together with --no-enum")

    cert_file = getattr(args, "cert", None)
    key_file = getattr(args, "key", None)
    if bool(cert_file) != bool(key_file):
        parser.error("--cert and --key must be supplied together")
    for option, path in (("--cert", cert_file), ("--key", key_file)):
        if path and (not os.path.isfile(path) or not os.access(path, os.R_OK)):
            parser.error(f"{option} is not a readable file: {path}")

    if getattr(args, "input_file", None):
        if not os.path.isfile(args.input_file):
            parser.error(f"--input-file does not exist or is not a file: {args.input_file}")
        if not os.access(args.input_file, os.R_OK):
            parser.error(f"--input-file is not readable: {args.input_file}")

    if getattr(args, "output_file", None):
        output_dir = os.path.dirname(os.path.abspath(args.output_file)) or "."
        if not os.path.isdir(output_dir):
            parser.error(f"--output-file directory does not exist: {output_dir}")
        if not os.access(output_dir, os.W_OK):
            parser.error(f"--output-file directory is not writable: {output_dir}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="tls-proxy-checker",
        description=(
            "Quickly check security-proxy TLS compatibility and certificate issues."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EPILOG,
    )
    parser.add_argument("-help", action="help", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("target",
                        nargs="?",
                        help="Host or URL (e.g. example.com or https://example.com)")
    parser.add_argument("--input-file", metavar="FILE",
                        help="Read targets from a text file and output one JSON report")
    parser.add_argument("--output-file", metavar="FILE",
                        help="Write JSON output to a file instead of stdout")
    parser.add_argument("--port",    type=int,   default=None,
                        help="TCP port (default: 443)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Socket timeout in seconds (default: 5)")
    parser.add_argument("--json",    action="store_true",
                        help="Write JSON output to stdout")
    parser.add_argument(
        "--profile",
        choices=sorted(INSPECTION_PROFILES),
        default=DEFAULT_PROFILE_ID,
        help=f"Proxy compatibility profile (default: {DEFAULT_PROFILE_ID})",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run exhaustive cipher and weak-suite diagnostics (slower)",
    )
    parser.add_argument(
        "--no-enum",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--no-protocols", action="store_true",
                        help="Skip per-version SSL/TLS protocol probes")
    parser.add_argument("--cert",    metavar="CERT_FILE",
                        help="Client certificate file (PEM) for mTLS endpoints")
    parser.add_argument("--key",     metavar="KEY_FILE",
                        help="Client private key file (PEM) for mTLS endpoints")
    args = parser.parse_args()
    validate_cli_paths(parser, args)
    if args.output_file:
        args.json = True

    if args.input_file:
        if args.target:
            parser.error("target cannot be used together with --input-file")
        output = build_batch_output(args)
        emit_json(output, args.output_file)
        return

    if not args.target:
        parser.error("target is required unless --input-file is used")
    try:
        parse_host(args.target)
    except ValueError as error:
        parser.error(f"invalid target: {error}")

    console = Console() if RICH_AVAILABLE else None

    # Warn if pyOpenSSL is missing
    if not HAS_PYOPENSSL and RICH_AVAILABLE and not args.json:
        console.print(Panel(
            Text(
                "pyopenssl not installed -- mTLS detection is limited.\n"
                "Run: pip install pyopenssl",
                style="bold yellow",
            ),
            title="[bold yellow]WARNING: Limited mTLS Detection",
            border_style="yellow",
        ))
    elif not HAS_PYOPENSSL and not RICH_AVAILABLE and not args.json:
        print("WARNING: pyopenssl not installed -- mTLS detection is limited.")
        print("         Run: pip install pyopenssl\n")

    if not RICH_AVAILABLE and not args.json:
        print("NOTE: 'rich' library not installed. Install with: pip install rich>=13.0.0")
        print("Falling back to plain text output.\n")

    if not args.json and not RICH_AVAILABLE:
        host, default_port = parse_host(args.target)
        port = args.port if args.port is not None else default_port
        print(f"Connecting to {host}:{port} ...")

    result = run_check(args.target, args, console=console if not args.json else None)

    # Output
    if args.json:
        emit_json(result, args.output_file)
        return

    host = result["host"]
    port = result["port"]
    conn = {
        "ip": result.get("ip"),
        "tls_version": result.get("tls_version"),
        "cipher": result.get("cipher"),
        "cert": result.get("certificate"),
        "handshake": result.get("handshake"),
        "error": result.get("error"),
    }
    enum_results = result.get("cipher_enumeration", [])
    protocol_results = result.get("protocol_support", [])
    security_assessment = result.get("security_assessment", {})
    inspection_assessment = result.get("inspection_verdict", {})
    mtls = result.get("mtls")

    if RICH_AVAILABLE:
        console.print()
        render_rich(
            host,
            port,
            conn,
            enum_results,
            mtls,
            protocol_results,
            security_assessment,
            inspection_assessment,
            args.timeout,
            console,
        )
    else:
        render_plain(
            host,
            port,
            conn,
            enum_results,
            mtls,
            protocol_results,
            security_assessment,
            inspection_assessment,
        )


if __name__ == "__main__":
    main()
