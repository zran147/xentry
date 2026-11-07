"""Static, allowlisted artifact mirror for target provisioning."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class MirrorError(RuntimeError):
    """The artifact mirror could not start or serve."""


def _load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        raise MirrorError(f"missing artifact manifest: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise MirrorError("artifact manifest has no artifacts")
    for name, entry in artifacts.items():
        if not isinstance(entry, dict) or not entry.get("path"):
            raise MirrorError(f"invalid artifact manifest entry: {name}")
        if not Path(str(entry["path"])).is_file():
            raise MirrorError(f"artifact file missing: {entry['path']}")
    return artifacts


class ArtifactMirror:
    def __init__(
        self,
        manifest_path: Path,
        *,
        bind: str = "10.42.0.1",
        port: int = 8081,
        allowed_ids: set[str] | None = None,
    ) -> None:
        self.manifest_path = Path(manifest_path)
        self.artifacts = _load_manifest(self.manifest_path)
        self.bind = bind
        self.port = port
        self.allowed_ids = allowed_ids
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            return self.bind, self.port
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    def start(self) -> None:
        mirror = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path = urlsplit(self.path).path
                parts = [part for part in path.split("/") if part]
                if len(parts) != 2 or parts[0] != "artifacts":
                    self.send_error(404)
                    return
                artifact_id = parts[1]
                if mirror.allowed_ids is not None and artifact_id not in mirror.allowed_ids:
                    self.send_error(404)
                    return
                entry = mirror.artifacts.get(artifact_id)
                if not isinstance(entry, dict):
                    self.send_error(404)
                    return
                file_path = Path(str(entry["path"]))
                try:
                    size = file_path.stat().st_size
                    handle = file_path.open("rb")
                except OSError:
                    self.send_error(404)
                    return
                with handle:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(size))
                    self.send_header("X-Checksum-Sha256", str(entry["sha256"]))
                    self.end_headers()
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)

            def log_message(self, *args: object) -> None:
                return

        server = ThreadingHTTPServer((self.bind, self.port), Handler)
        server.daemon_threads = True
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, name="xentry-mirror", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
