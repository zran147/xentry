#!/usr/bin/env python3
"""Run the Phase 0 extractor gate against the fact fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from xentry.extract import ArtifactText, ExtractorError, extract
from xentry.targets import by_cve

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "facts"


def _check(actual: Any, op: str, expected: Any) -> bool:
    if op == "equals":
        return actual == expected
    if op == "in":
        return actual in expected
    if op == "nonempty":
        return bool(actual)
    if op == "contains":
        if isinstance(actual, list):
            return any(str(expected).lower() in str(item).lower() for item in actual)
        return str(expected).lower() in str(actual).lower()
    if op == "contains_any":
        if isinstance(actual, list):
            text = " ".join(str(item) for item in actual)
        else:
            text = str(actual)
        return any(str(item).lower() in text.lower() for item in expected)
    raise ValueError(f"unknown check op: {op}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", choices=("adk", "litellm"), default="adk")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    args = parser.parse_args()

    passed = 0
    total = 0
    invalid_safe = 0
    invalid_total = 0
    failures: list[str] = []
    results: list[dict[str, Any]] = []
    for path in sorted(args.fixtures.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        artifact = ArtifactText(
            artifact_id=fixture["case_id"],
            sha256=fixture["artifact_sha256"],
            text=fixture["text"],
        )
        if fixture["valid"]:
            try:
                facts = extract([artifact], runtime=args.runtime)
            except ExtractorError as exc:
                results.append({"case_id": fixture["case_id"], "error": exc.code})
                failures.append(f"{fixture['case_id']}: {exc.code}")
                total += len(fixture["checks"])
                continue
            for check in fixture["checks"]:
                total += 1
                actual = getattr(facts, check["field"])
                ok = _check(actual, check["op"], check.get("value"))
                if ok:
                    passed += 1
                else:
                    failures.append(
                        f"{fixture['case_id']}:{check['field']} expected "
                        f"{check['op']} {check['value']!r}, got {actual!r}"
                    )
            results.append(
                {
                    "case_id": fixture["case_id"],
                    "citations": len(facts.citations),
                    "cve_id": facts.cve_id,
                }
            )
        else:
            invalid_total += 1
            try:
                facts = extract([artifact], runtime=args.runtime)
                safe = by_cve(facts.cve_id) is None
                if safe:
                    invalid_safe += 1
                results.append(
                    {
                        "case_id": fixture["case_id"],
                        "invalid_safe": safe,
                        "cve_id": facts.cve_id,
                    }
                )
            except ExtractorError:
                invalid_safe += 1
                results.append({"case_id": fixture["case_id"], "invalid_safe": True})

    summary = {
        "runtime": args.runtime,
        "facts_passed": passed,
        "facts_total": total,
        "invalid_safe": invalid_safe,
        "invalid_total": invalid_total,
        "results": results,
        "failures": failures,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if passed >= 19 and total >= 20 and invalid_safe == invalid_total else 1


if __name__ == "__main__":
    raise SystemExit(main())
