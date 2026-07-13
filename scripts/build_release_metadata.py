#!/usr/bin/env python3
"""Generate machine-readable metadata for a standalone release binary."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.metadata
import json
import os
import platform
import ssl
from pathlib import Path

from tls_proxy_checker import __version__


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dependency_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def cryptography_openssl_version() -> str | None:
    try:
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.openssl_version_text()
    except (ImportError, AttributeError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--glibc-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    glibc_report = json.loads(args.glibc_report.read_text(encoding="utf-8"))
    report = {
        "schema_version": 1,
        "name": "tls-proxy-checker",
        "version": __version__,
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "source": {
            "repository": "https://github.com/EggertsIT/tls-proxy-checker",
            "commit": os.environ.get("GITHUB_SHA"),
        },
        "artifact": {
            "file": args.binary.name,
            "format": "ELF 64-bit executable",
            "architecture": platform.machine(),
            "size_bytes": args.binary.stat().st_size,
            "sha256": sha256(args.binary),
        },
        "runtime": {
            "os": "Linux",
            "minimum_glibc": glibc_report.get("required_glibc"),
            "requires_python": False,
        },
        "build": {
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "stdlib_openssl": ssl.OPENSSL_VERSION,
            "cryptography_openssl": cryptography_openssl_version(),
            "pyinstaller": dependency_version("pyinstaller"),
            "cryptography": dependency_version("cryptography"),
            "pyopenssl": dependency_version("pyOpenSSL"),
            "rich": dependency_version("rich"),
        },
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
