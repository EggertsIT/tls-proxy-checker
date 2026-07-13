#!/usr/bin/env python3
"""Run the supported BadSSL regression cases against the scanner."""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from tls_proxy_checker import __version__
from tls_proxy_checker.cli import emit_json, run_check
from tls_proxy_checker.profiles import DEFAULT_PROFILE_ID


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests" / "badssl_cases.json"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify supported BadSSL cases against stable finding IDs."
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--output", help="Write the verification report as JSON")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retry a case after a transient scan error (default: 1)",
    )
    parser.add_argument(
        "--include-unstable",
        action="store_true",
        help="Include BadSSL endpoints that upstream classifies as defunct",
    )
    parser.add_argument(
        "--only",
        help="Comma-separated target names to run instead of the full supported set",
    )
    return parser.parse_args()


def scanner_arguments(scan_mode: str, timeout: float) -> SimpleNamespace:
    return SimpleNamespace(
        port=None,
        timeout=timeout,
        json=True,
        full=scan_mode == "full",
        no_enum=False,
        no_protocols=scan_mode == "quick",
        profile=DEFAULT_PROFILE_ID,
        cert=None,
        key=None,
    )


def main() -> int:
    args = parse_arguments()
    if args.retries < 0:
        raise SystemExit("--retries must be zero or greater")
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    selected_targets = (
        {item.strip() for item in args.only.split(",") if item.strip()}
        if args.only
        else None
    )

    supported_coverages = {"automated", "automated_with_openssl"}
    if args.include_unstable:
        supported_coverages.add("automated_unstable")

    cases = [
        case
        for case in manifest["cases"]
        if case["coverage"] in supported_coverages
        and (selected_targets is None or case.get("target") in selected_targets)
    ]
    if selected_targets is not None:
        found_targets = {case["target"] for case in cases}
        unknown = sorted(selected_targets - found_targets)
        if unknown:
            print(
                "Targets are absent or not automated: " + ", ".join(unknown),
                file=sys.stderr,
            )
            return 2

    started_at = datetime.datetime.now(datetime.timezone.utc)
    results = []
    for case in cases:
        expected = set(case["expected_findings"])
        attempt_errors = []
        for attempt in range(args.retries + 1):
            result = run_check(
                case["target"],
                scanner_arguments(case["scan"], args.timeout),
                console=None,
            )
            observed = {
                finding["id"]
                for finding in result.get("security_assessment", {}).get(
                    "findings", []
                )
            }
            missing = sorted(expected - observed)
            if not missing or not result.get("error") or attempt == args.retries:
                break
            attempt_errors.append(result["error"])
            print(
                f"RETRY {case['target']} after transient error: "
                f"{result['error']}"
            )
        passed = not missing
        print(f"{'PASS' if passed else 'FAIL'}  {case['target']}")
        if missing:
            print("      missing: " + ", ".join(missing))
        results.append(
            {
                "target": case["target"],
                "category": case["category"],
                "scan": case["scan"],
                "passed": passed,
                "expected_findings": sorted(expected),
                "observed_findings": sorted(observed),
                "missing_findings": missing,
                "scan_error": result.get("error"),
                "attempt_count": len(attempt_errors) + 1,
                "transient_errors": attempt_errors,
            }
        )

    finished_at = datetime.datetime.now(datetime.timezone.utc)
    report = {
        "schema_version": 1,
        "tool": "tls-proxy-checker-badssl-verifier",
        "tool_version": __version__,
        "source": manifest["source"],
        "source_revision": manifest["source_revision"],
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "finished_at": finished_at.isoformat().replace("+00:00", "Z"),
        "case_count": len(results),
        "passed": sum(item["passed"] for item in results),
        "failed": sum(not item["passed"] for item in results),
        "results": results,
    }
    if args.output:
        emit_json(report, args.output)
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
