"""Append-only per-attempt event journal with a hash chain.

The journal lives beside the attempt artifacts. It records state transitions
and hashes, never nonce values or raw evidence bytes. Each record carries the
hash of the previous record so truncation or edits are detectable.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FIELDS = ("type", "ts", "payload", "prev_hash")


def _canonical(record: dict[str, Any]) -> str:
    body = {key: record.get(key) for key in FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _last_hash(path: Path) -> str:
    if not path.is_file():
        return ""
    last = ""
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                last = line
    if not last:
        return ""
    try:
        return str(json.loads(last).get("hash", ""))
    except json.JSONDecodeError:
        return ""


def append(path: Path, event_type: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "type": event_type,
        "ts": datetime.now(UTC).isoformat(),
        "payload": payload or {},
        "prev_hash": _last_hash(path),
    }
    record["hash"] = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def read(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def verify(path: Path) -> bool:
    previous = ""
    for record in read(path):
        if record.get("prev_hash") != previous:
            return False
        expected = hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()
        if record.get("hash") != expected:
            return False
        previous = str(record["hash"])
    return True
