"""Artifact mirror tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx

from broker.mirror import ArtifactMirror


def _manifest(tmp_path: Path, artifact_id: str = "php-8.4.26-src") -> tuple[Path, bytes]:
    payload = b"pinned artifact bytes"
    artifact = tmp_path / "php.tar.xz"
    artifact.write_bytes(payload)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "artifacts": {
                    artifact_id: {
                        "kind": "package",
                        "path": str(artifact),
                        "filename": "php.tar.xz",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return manifest, payload


def test_mirror_serves_allowlisted_artifact(tmp_path: Path) -> None:
    manifest, payload = _manifest(tmp_path)
    mirror = ArtifactMirror(manifest, bind="127.0.0.1", port=0)
    mirror.start()
    try:
        response = httpx.get(f"{mirror.url}/artifacts/php-8.4.26-src", timeout=5.0)
        assert response.status_code == 200
        assert response.content == payload
        assert response.headers["X-Checksum-Sha256"] == hashlib.sha256(payload).hexdigest()
        assert httpx.get(f"{mirror.url}/artifacts/unknown", timeout=5.0).status_code == 404
        assert httpx.get(f"{mirror.url}/", timeout=5.0).status_code == 404
    finally:
        mirror.stop()


def test_mirror_can_restrict_to_a_job_manifest(tmp_path: Path) -> None:
    manifest, _ = _manifest(tmp_path)
    mirror = ArtifactMirror(
        manifest,
        bind="127.0.0.1",
        port=0,
        allowed_ids={"some-other-artifact"},
    )
    mirror.start()
    try:
        assert httpx.get(f"{mirror.url}/artifacts/php-8.4.26-src", timeout=5.0).status_code == 404
    finally:
        mirror.stop()
