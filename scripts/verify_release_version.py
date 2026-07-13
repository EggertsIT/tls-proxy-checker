#!/usr/bin/env python3
"""Verify that a release tag matches all project version declarations."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
INIT_FILE = ROOT / "src" / "tls_proxy_checker" / "__init__.py"


def declared_versions() -> dict[str, str]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    init_text = INIT_FILE.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', init_text, re.MULTILINE)
    if not match:
        raise ValueError(f"version declaration not found in {INIT_FILE}")
    return {
        "pyproject.toml": pyproject["project"]["version"],
        str(INIT_FILE.relative_to(ROOT)): match.group(1),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag", help="Release tag in vMAJOR.MINOR.PATCH form")
    args = parser.parse_args()

    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.tag):
        parser.error("tag must use vMAJOR.MINOR.PATCH format")

    expected = args.tag[1:]
    mismatches = {
        source: version
        for source, version in declared_versions().items()
        if version != expected
    }
    if mismatches:
        for source, version in mismatches.items():
            print(
                f"{source}: expected {expected}, found {version}",
                file=sys.stderr,
            )
        return 1

    print(f"Release version {expected} is consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
