#!/usr/bin/env python3
"""Refresh the sha256 values in targets/steps.yaml after a script edit."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "targets" / "steps.yaml"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    data = yaml.safe_load(MANIFEST.read_text(encoding="utf-8")) or {}
    steps = data.get("steps") or {}
    for step_id, spec in steps.items():
        script = ROOT / "targets" / str(spec["script"])
        if not script.is_file():
            raise SystemExit(f"{step_id}: missing {script}")
        spec["sha256"] = sha256(script)
        print(f"{step_id}: {spec['sha256']}")
    MANIFEST.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
