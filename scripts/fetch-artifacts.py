#!/usr/bin/env python3
"""Validate or download the pinned Gate G artifact catalog."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from xentry.artifact_tools import download_to, hash_file, now_iso, validate_sha256

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "config" / "artifacts.yaml"
DEFAULT_OUT = ROOT / "var" / "artifacts"
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")


def filename_for(url: str) -> str:
    name = Path(urlsplit(url).path).name
    if not name:
        raise ValueError(f"URL has no filename: {url}")
    return name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--mode", choices=("dry-run", "download"), default="dry-run")
    args = parser.parse_args()

    data = yaml.safe_load(args.catalog.read_text(encoding="utf-8")) or {}
    artifacts = data.get("artifacts") or {}
    errors: list[str] = []
    manifest: dict[str, dict[str, object]] = {}
    if not artifacts:
        errors.append("catalog has no artifacts")
    for name, artifact in artifacts.items():
        if not SAFE_ID.fullmatch(name):
            errors.append(f"{name}: unsafe artifact id")
            continue
        if not isinstance(artifact, dict):
            errors.append(f"{name}: entry is not a mapping")
            continue
        for field in ("kind", "url", "sha256", "provenance", "status"):
            if not artifact.get(field):
                errors.append(f"{name}: missing {field}")
        sha = str(artifact.get("sha256", ""))
        if sha:
            try:
                validate_sha256(sha)
            except ValueError as exc:
                errors.append(f"{name}: {exc}")
        if artifact.get("status") != "resolved":
            errors.append(f"{name}: status is unresolved (Gate G)")
        url = str(artifact.get("url", ""))
        if not url or artifact.get("kind") == "image":
            continue
        if url.startswith("build://"):
            # Built here rather than fetched: an npm closure, say. There is
            # nothing to download, but the broker resolves copy_in against this
            # manifest, so a bundle that is on disk and matches its pin has to
            # appear in it or the job fails with "unknown artifact_id" long
            # after the operator thought they had pinned it.
            if args.mode == "download":
                local = args.out / name / f"{name}.tar.gz"
                if not local.is_file():
                    errors.append(f"{name}: pinned but not installed at {local}")
                elif hash_file(local) != sha:
                    errors.append(f"{name}: {local} does not match its pin")
                else:
                    manifest[name] = {
                        "kind": artifact.get("kind"),
                        "path": str(local),
                        "filename": local.name,
                        "sha256": sha,
                    }
                    print(f"registered {name}: {sha} ({local})")
            continue
        if args.mode == "download":
            try:
                filename = filename_for(url)
                dest = args.out / name / filename
                actual = download_to(url, dest, sha)
                manifest[name] = {
                    "kind": artifact.get("kind"),
                    "path": str(dest),
                    "filename": filename,
                    "sha256": actual,
                }
                print(f"verified {name}: {actual} ({dest})")
            except Exception as exc:  # noqa: BLE001 - report every download failure
                errors.append(f"{name}: download failed: {exc}")

    if errors:
        print("Artifact gate G: BLOCKED")
        for error in errors:
            print(f" - {error}")
        return 1
    if args.mode == "download":
        manifest_path = args.out / "manifest.json"
        manifest_path.write_text(
            json.dumps({"generated_at": now_iso(), "artifacts": manifest}, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        print(f"Artifact manifest: {manifest_path}")
    print("Artifact gate G: PASS")
    if args.mode == "dry-run":
        print("Dry run only; no artifacts were downloaded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
