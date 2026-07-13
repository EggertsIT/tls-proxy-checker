import argparse
import json
import sys

import pytest

from scripts import check_glibc
from scripts.check_glibc import format_glibc_version, parse_glibc_version


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2.35", (2, 35)),
        ("10.2", (10, 2)),
    ],
)
def test_parse_glibc_version(value, expected):
    assert parse_glibc_version(value) == expected


@pytest.mark.parametrize("value", ["2", "2.35.1", "v2.35", "two.35", ""])
def test_parse_glibc_version_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_glibc_version(value)


def test_format_glibc_version():
    assert format_glibc_version((2, 35)) == "2.35"
    assert format_glibc_version(None) is None


@pytest.mark.parametrize(
    ("required", "expected_exit", "within_maximum"),
    [
        ((2, 35), 0, True),
        ((2, 36), 2, False),
    ],
)
def test_main_enforces_maximum_glibc(
    monkeypatch, tmp_path, capsys, required, expected_exit, within_maximum
):
    elf_path = tmp_path / "binary"
    elf_path.write_bytes(b"\x7fELF")
    monkeypatch.setattr(check_glibc, "elf_files", lambda paths: iter([elf_path]))
    monkeypatch.setattr(
        check_glibc,
        "required_glibc",
        lambda path, readelf: [required],
    )
    monkeypatch.setattr(check_glibc.shutil, "which", lambda name: "/usr/bin/readelf")
    monkeypatch.setattr(
        sys,
        "argv",
        ["check_glibc.py", str(elf_path), "--maximum", "2.35", "--json"],
    )

    assert check_glibc.main() == expected_exit
    report = json.loads(capsys.readouterr().out)
    assert report["required_glibc"] == format_glibc_version(required)
    assert report["maximum_allowed_glibc"] == "2.35"
    assert report["within_maximum"] is within_maximum
