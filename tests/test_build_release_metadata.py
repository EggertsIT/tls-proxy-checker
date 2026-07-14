import argparse
import json
import sys

import pytest

from scripts import build_release_metadata


def test_parse_sha256_normalizes_digest():
    digest = "A" * 64

    assert build_release_metadata.parse_sha256(digest) == digest.lower()


@pytest.mark.parametrize("digest", ["", "a" * 63, "a" * 65, "g" * 64])
def test_parse_sha256_rejects_invalid_digest(digest):
    with pytest.raises(argparse.ArgumentTypeError):
        build_release_metadata.parse_sha256(digest)


def test_main_records_pinned_python_distribution(monkeypatch, tmp_path):
    binary = tmp_path / "tls-proxy-checker-linux-x86_64"
    binary.write_bytes(b"standalone release binary")
    glibc_report = tmp_path / "glibc-requirements.json"
    glibc_report.write_text(
        json.dumps({"required_glibc": "2.17"}),
        encoding="utf-8",
    )
    output = tmp_path / "BUILDINFO.json"
    distribution_url = "https://example.invalid/cpython.tar.gz"
    distribution_sha256 = "1" * 64
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build_release_metadata.py",
            "--binary",
            str(binary),
            "--glibc-report",
            str(glibc_report),
            "--python-distribution-url",
            distribution_url,
            "--python-distribution-sha256",
            distribution_sha256,
            "--output",
            str(output),
        ],
    )

    assert build_release_metadata.main() == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["build"]["python_distribution"] == {
        "url": distribution_url,
        "sha256": distribution_sha256,
    }
    assert report["source"]["commit"] == "a" * 40
    assert report["runtime"]["minimum_glibc"] == "2.17"
