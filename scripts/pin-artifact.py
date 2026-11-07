#!/usr/bin/env python3
"""Explicitly pin one artifact after operator review.

This command is the only writer of config/artifacts.yaml. It requires --accept,
a source, and a SHA-256; for non-build URLs it downloads the bytes and verifies
the hash before writing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from xentry.artifact_tools import fetch_and_hash, load_catalog, validate_sha256, write_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "artifacts.yaml"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--url", default="")
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--commit", default="")
    parser.add_argument("--source", required=True, help="vendor URL or build-script provenance")
    parser.add_argument("--accept", action="store_true", help="confirm the operator reviewed the source")
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    args = parser.parse_args()

    if not args.accept:
        print("refusing to pin without --accept", file=sys.stderr)
        return 2
    try:
        sha = validate_sha256(args.sha256)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    data = load_catalog(args.catalog)
    artifacts = data.setdefault("artifacts", {})
    if args.artifact not in artifacts:
        print(f"unknown artifact: {args.artifact}", file=sys.stderr)
        return 2

    artifact = artifacts[args.artifact]
    url = args.url or artifact.get("url", "")
    if url.startswith("build://"):
        print("build artifact: hash must come from the build script; source recorded", file=sys.stderr)
    elif url:
        actual, size = fetch_and_hash(url, timeout=600.0)
        if actual != sha:
            print(f"hash mismatch: expected {sha}, downloaded {actual} ({size} bytes)", file=sys.stderr)
            return 1
        print(f"verified {url}: {actual} ({size} bytes)")
    else:
        print("no URL and not a build artifact; refusing to pin", file=sys.stderr)
        return 2

    artifact.update(
        {
            "url": url,
            "sha256": sha,
            "provenance": args.source,
            "status": "resolved",
        }
    )
    if args.commit:
        artifact["commit"] = args.commit
    write_catalog(args.catalog, data)
    print(f"pinned {args.artifact} in {args.catalog}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
