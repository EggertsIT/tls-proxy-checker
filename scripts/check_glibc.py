#!/usr/bin/env python3
"""Report the highest GLIBC symbol required by ELF files under given paths."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path


GLIBC_PATTERN = re.compile(r"GLIBC_(\d+)\.(\d+)")
GLIBC_VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)$")


def parse_glibc_version(value: str) -> tuple[int, int]:
    match = GLIBC_VERSION_PATTERN.fullmatch(value)
    if not match:
        raise argparse.ArgumentTypeError("expected a GLIBC version such as 2.17")
    return int(match.group(1)), int(match.group(2))


def format_glibc_version(version: tuple[int, int] | None) -> str | None:
    return f"{version[0]}.{version[1]}" if version else None


def elf_files(paths: list[Path]):
    for path in paths:
        candidates = path.rglob("*") if path.is_dir() else [path]
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                with candidate.open("rb") as handle:
                    if handle.read(4) == b"\x7fELF":
                        yield candidate
            except OSError:
                continue


def required_glibc(path: Path, readelf: str) -> list[tuple[int, int]]:
    completed = subprocess.run(
        [readelf, "--version-info", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )  # nosec B603
    return sorted(
        {
            (int(match.group(1)), int(match.group(2)))
            for match in GLIBC_PATTERN.finditer(completed.stdout + completed.stderr)
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find the maximum GLIBC symbol version required by ELF files."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--maximum",
        type=parse_glibc_version,
        metavar="MAJOR.MINOR",
        help="Fail if any bundled ELF requires a newer GLIBC version",
    )
    args = parser.parse_args()

    readelf = shutil.which("readelf")
    if not readelf:
        parser.error("readelf is required")

    records = []
    maximum = None
    for path in elf_files(args.paths):
        versions = required_glibc(path, readelf)
        if not versions:
            continue
        required = versions[-1]
        maximum = max(maximum, required) if maximum else required
        records.append(
            {
                "path": str(path),
                "required_glibc": f"{required[0]}.{required[1]}",
            }
        )

    records.sort(
        key=lambda item: tuple(int(part) for part in item["required_glibc"].split(".")),
        reverse=True,
    )
    report = {
        "required_glibc": format_glibc_version(maximum),
        "maximum_allowed_glibc": format_glibc_version(args.maximum),
        "within_maximum": (
            maximum <= args.maximum if maximum and args.maximum else None
        ),
        "elf_file_count": len(records),
        "files": records,
    }
    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Required GLIBC: {report['required_glibc'] or 'not detected'}")
        for item in records[:20]:
            print(f"  {item['required_glibc']:<8} {item['path']}")
    if not maximum:
        return 1
    if args.maximum and maximum > args.maximum:
        print(
            f"Required GLIBC {format_glibc_version(maximum)} exceeds "
            f"the allowed maximum {format_glibc_version(args.maximum)}.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
