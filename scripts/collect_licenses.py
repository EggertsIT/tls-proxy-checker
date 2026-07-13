#!/usr/bin/env python3
"""Collect dependency license files for a standalone binary archive."""

from __future__ import annotations

import argparse
import importlib.metadata
import shutil
import sys
import sysconfig
from pathlib import Path


DISTRIBUTIONS = (
    "cryptography",
    "pyOpenSSL",
    "rich",
    "markdown-it-py",
    "mdurl",
    "Pygments",
    "cffi",
    "pycparser",
    "pyinstaller",
)
LICENSE_PREFIXES = ("license", "copying", "authors", "notice")


def collect_distribution_licenses(name: str, output_dir: Path) -> int:
    distribution = importlib.metadata.distribution(name)
    copied = 0
    for relative_path in distribution.files or ():
        if not relative_path.name.lower().startswith(LICENSE_PREFIXES):
            continue
        source = Path(distribution.locate_file(relative_path))
        if not source.is_file():
            continue
        destination = output_dir / f"{name}-{relative_path.name}"
        shutil.copyfile(source, destination)
        copied += 1
    if copied == 0:
        raise RuntimeError(f"no license file found for {name}")
    return copied


def collect_python_license(output_dir: Path) -> None:
    base_prefix = Path(sys.base_prefix).resolve()
    search_roots = (base_prefix, *tuple(base_prefix.parents)[:6])
    candidates = tuple(
        root / filename
        for root in search_roots
        for filename in ("LICENSE", "LICENSE.txt")
    ) + (
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
        Path(sysconfig.get_path("stdlib")) / "LICENSE",
    )
    source = next((path for path in candidates if path.is_file()), None)
    if source is None:
        raise RuntimeError("CPython license file was not found")
    shutil.copyfile(source, output_dir / "CPython-LICENSE.txt")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    collect_python_license(args.output_dir)
    count = 1
    for name in DISTRIBUTIONS:
        count += collect_distribution_licenses(name, args.output_dir)
    print(f"Collected {count} license files in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
