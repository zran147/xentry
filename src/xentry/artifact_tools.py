"""Operator helpers for artifact research and explicit pinning.

Research is not a trust root. Candidates are written to var/research and must be
reviewed by the operator. Pinning requires an explicit --accept and verifies the
downloaded bytes against the supplied SHA-256.
"""

from __future__ import annotations

import gzip
import hashlib
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
USER_AGENT = "xentry-artifact-research/0.1"


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def validate_sha256(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value or ""):
        raise ValueError("sha256 must be 64 lowercase hex characters")
    return value


def parse_sha256sums(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            result[parts[-1].lstrip("*")] = parts[0]
    return result


def extract_hashes(text: str) -> list[str]:
    return sorted(set(SHA256_RE.findall(text)))


def extract_urls(text: str) -> list[str]:
    return sorted(set(URL_RE.findall(text)))


def load_catalog(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def write_catalog(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix="artifacts.", suffix=".yaml", dir=path.parent)
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            yaml.safe_dump(data, handle, sort_keys=False)
        Path(tmp_name).replace(path)
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def fetch_text(url: str, max_bytes: int = 50_000, timeout: float = 20.0) -> str:
    response = httpx.get(
        url,
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    return response.text[:max_bytes]


def fetch_and_hash(url: str, timeout: float = 60.0) -> tuple[str, int]:
    """Download a URL and return (sha256, bytes). The bytes are not kept."""
    digest = hashlib.sha256()
    total = 0
    with httpx.stream(
        "GET",
        url,
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    ) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_to(url: str, dest: Path, expected_sha: str, timeout: float = 600.0) -> str:
    """Download to dest, verify the SHA-256, and keep the bytes."""
    validate_sha256(expected_sha)
    if dest.exists() and hash_file(dest) == expected_sha:
        return expected_sha
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    digest = hashlib.sha256()
    with httpx.stream(
        "GET",
        url,
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    ) as response:
        response.raise_for_status()
        with part.open("wb") as handle:
            for chunk in response.iter_bytes():
                handle.write(chunk)
                digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected_sha:
        part.unlink(missing_ok=True)
        raise ValueError(f"hash mismatch for {url}: expected {expected_sha}, got {actual}")
    part.replace(dest)
    return actual


def fetch_gzip_text(url: str, max_bytes: int = 8_000_000, timeout: float = 60.0) -> str:
    response = httpx.get(
        url,
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    if len(response.content) > max_bytes:
        raise ValueError(f"{url}: gzip payload larger than {max_bytes} bytes")
    return gzip.decompress(response.content).decode("utf-8", "replace")


def parse_deb822(text: str) -> list[dict[str, str]]:
    """Parse an apt Packages index into one mapping per package stanza."""
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith((" ", "\t")):
            continue
        key, sep, value = line.partition(":")
        if sep:
            current[key.strip()] = value.strip()
    if current:
        entries.append(current)
    return entries


def github_latest_commit(repo: str, branch: str = "") -> dict[str, str]:
    if branch:
        url = f"https://api.github.com/repos/{repo}/commits/{branch}"
    else:
        url = f"https://api.github.com/repos/{repo}/commits?per_page=1"
    response = httpx.get(
        url,
        follow_redirects=True,
        timeout=20.0,
        headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
    )
    response.raise_for_status()
    payload = response.json()
    if branch:
        commit = payload
    else:
        if not payload:
            raise ValueError(f"no commits for {repo}")
        commit = payload[0]
    sha = commit["sha"]
    return {
        "commit": sha,
        "source_url": commit["html_url"],
        "tarball_url": f"https://github.com/{repo}/archive/{sha}.tar.gz",
    }


def candidate(
    *,
    artifact_id: str,
    url: str = "",
    version: str = "",
    sha256: str = "",
    commit: str = "",
    source_url: str = "",
    method: str = "regex",
    notes: str = "",
) -> dict[str, str]:
    return {
        "artifact_id": artifact_id,
        "url": url,
        "version": version,
        "sha256": sha256,
        "commit": commit,
        "source_url": source_url,
        "method": method,
        "notes": notes,
        "retrieved_at": now_iso(),
    }
