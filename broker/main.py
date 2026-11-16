"""Root-owned Unix-socket broker.

The broker accepts one newline-delimited JSON request per connection, checks the
peer UID, resolves every id through the broker-owned registry, dispatches a fixed
verb, and appends a broker_calls record. Resource operations are stubs until the
libvirt, network, SSH, and host-evidence layers are implemented.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import socket
import stat
import struct
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from broker.errors import BrokerError
from broker.registry import (
    RegistryError,
    resolve_artifact,
    resolve_image,
    resolve_profile,
    resolve_step,
    resolve_target,
)

MAX_REQUEST_BYTES = 1_048_576
JOB_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
OWNER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

VERB_PARAMS: dict[str, frozenset[str]] = {
    "ping": frozenset(),
    "resolve_target": frozenset({"target_id"}),
    "resolve_profile": frozenset({"profile_id"}),
    "resolve_image": frozenset({"image_id"}),
    "resolve_artifact": frozenset({"artifact_id"}),
    "resolve_step": frozenset({"step_id"}),
    "list_managed": frozenset(),
    "create_network": frozenset(
        {"job_id", "profile_id", "apt_snapshot", "apt_archive", "registry_cutoff"}
    ),
    "lock_network": frozenset({"job_id", "target_ports"}),
    "create_target": frozenset({"job_id", "target_id", "image_id"}),
    "create_attacker": frozenset({"job_id", "profile_id", "image_id"}),
    "exec": frozenset({"vm_id", "step_id", "params", "tty", "timeout_s", "trace"}),
    "cancel_exec": frozenset({"vm_id", "request_id"}),
    "copy_in": frozenset({"vm_id", "artifact_id", "guest_path"}),
    "stage_artifact": frozenset({"job_id", "artifact_id", "path", "sha256"}),
    "copy_out": frozenset({"vm_id", "guest_path"}),
    "place_nonce": frozenset({"vm_id", "nonce_id", "path", "owner", "mode", "value"}),
    "snapshot": frozenset({"vm_id", "kind"}),
    "restore": frozenset({"vm_id", "snapshot_id"}),
    "reboot": frozenset({"vm_id", "timeout_s"}),
    "read_host_evidence": frozenset({"vm_id", "channel"}),
    "http_probe": frozenset(
        {"vm_id", "network_id", "port", "method", "path", "timeout_s", "max_bytes"}
    ),
    "proxy_capture": frozenset({"vm_id", "network_id", "target_port", "timeout_s"}),
    "start_artifact_mirror": frozenset({"job_id", "manifest_id"}),
    "stop_artifact_mirror": frozenset({"job_id"}),
    "destroy_vm": frozenset({"vm_id"}),
    "destroy_network": frozenset({"network_id"}),
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _require(params: dict[str, Any], *keys: str) -> None:
    missing = [key for key in keys if key not in params]
    if missing:
        raise BrokerError("broker_registry_rejected", f"missing params: {missing}")


def _text(params: dict[str, Any], key: str, max_len: int = 256) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise BrokerError("broker_registry_rejected", f"invalid {key}")
    return value


def _integer(params: dict[str, Any], key: str, minimum: int, maximum: int) -> int:
    value = params.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise BrokerError("broker_registry_rejected", f"invalid {key}")
    if not minimum <= value <= maximum:
        raise BrokerError("broker_registry_rejected", f"{key} out of range")
    return value


def _guest_path(params: dict[str, Any], key: str = "guest_path") -> str:
    value = _text(params, key, max_len=400)
    if value.startswith("/") or ".." in Path(value).parts or "\\" in value:
        raise BrokerError("broker_registry_rejected", f"invalid {key}")
    return value


def _nonce_path(params: dict[str, Any]) -> str:
    value = _text(params, "path", max_len=400)
    if not value.startswith("/") or ".." in Path(value).parts:
        raise BrokerError("broker_registry_rejected", "invalid nonce path")
    return value


def _step(params: dict[str, Any]) -> dict[str, Any]:
    step = resolve_step(_text(params, "step_id"))
    return {
        "step_id": step.step_id,
        "allowed_users": list(step.allowed_users),
        "broker_side": step.broker_side,
    }


def _ping(_: dict[str, Any]) -> dict[str, Any]:
    return {"pong": True}


def _list_managed(_: dict[str, Any]) -> dict[str, Any]:
    return {"domains": [], "networks": []}


def _create_network(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "job_id", "profile_id")
    return {
        "status": "not_implemented",
        "job_id": _text(params, "job_id"),
        "profile_id": resolve_profile(_text(params, "profile_id")),
    }


def _create_target(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "job_id", "target_id", "image_id")
    return {
        "status": "not_implemented",
        "job_id": _text(params, "job_id"),
        "target_id": resolve_target(_text(params, "target_id")),
        "image_id": resolve_image(_text(params, "image_id")),
    }


def _create_attacker(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "job_id", "profile_id", "image_id")
    return {
        "status": "not_implemented",
        "job_id": _text(params, "job_id"),
        "profile_id": resolve_profile(_text(params, "profile_id")),
        "image_id": resolve_image(_text(params, "image_id")),
    }


def _exec(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "step_id")
    vm_id = _text(params, "vm_id")
    step = _step(params)
    inner = params.get("params", {})
    if not isinstance(inner, dict):
        raise BrokerError("broker_registry_rejected", "params must be an object")
    forbidden = {"argv", "command", "shell", "user"} & set(inner)
    if forbidden:
        raise BrokerError("broker_registry_rejected", f"raw command rejected: {sorted(forbidden)}")
    tty = params.get("tty", False)
    if not isinstance(tty, bool):
        raise BrokerError("broker_registry_rejected", "invalid tty")
    trace = params.get("trace", False)
    if not isinstance(trace, bool):
        raise BrokerError("broker_registry_rejected", "invalid trace")
    timeout_s = _integer(params, "timeout_s", 1, 1800)
    return {
        "status": "not_implemented",
        "vm_id": vm_id,
        **step,
        "tty": tty,
        "timeout_s": timeout_s,
        "trace": trace,
    }


def _copy_in(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "artifact_id", "guest_path")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "artifact_id": resolve_artifact(_text(params, "artifact_id")),
        "guest_path": _guest_path(params),
    }


def _stage_artifact(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "job_id", "artifact_id", "path", "sha256")
    return {"status": "not_implemented", "artifact_id": _text(params, "artifact_id")}


def _copy_out(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "guest_path")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "guest_path": _guest_path(params),
    }


def _place_nonce(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "nonce_id", "path", "owner", "mode", "value")
    owner = _text(params, "owner", max_len=32)
    if not OWNER_RE.fullmatch(owner):
        raise BrokerError("broker_registry_rejected", "invalid nonce owner")
    mode = _integer(params, "mode", 0, 0o777)
    value = _text(params, "value", max_len=256)
    if len(value) < 16:
        raise BrokerError("broker_registry_rejected", "nonce value too short")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "nonce_id": _text(params, "nonce_id"),
        "path": _nonce_path(params),
        "owner": owner,
        "mode": mode,
        "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }


def _snapshot(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "kind")
    kind = _text(params, "kind")
    if kind not in {"disk", "memory"}:
        raise BrokerError("broker_registry_rejected", "invalid snapshot kind")
    return {"status": "not_implemented", "vm_id": _text(params, "vm_id"), "kind": kind}


def _restore(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "snapshot_id")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "snapshot_id": _text(params, "snapshot_id"),
    }


def _reboot(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "timeout_s": _integer(params, "timeout_s", 1, 600),
    }


def _read_host_evidence(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "channel")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "channel": _text(params, "channel"),
    }


def _http_probe(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "network_id", "port", "method", "path")
    method = _text(params, "method", max_len=8).upper()
    if method not in {"GET", "HEAD"}:
        raise BrokerError("broker_registry_rejected", "invalid HTTP method")
    path = _text(params, "path", max_len=1024)
    if not path.startswith("/"):
        raise BrokerError("broker_registry_rejected", "invalid HTTP path")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "network_id": _text(params, "network_id"),
        "port": _integer(params, "port", 1, 65535),
        "method": method,
        "path": path,
        "timeout_s": _integer(params, "timeout_s", 1, 120),
        "max_bytes": _integer(params, "max_bytes", 1, 1_000_000),
    }


def _proxy_capture(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "network_id", "target_port")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "network_id": _text(params, "network_id"),
        "target_port": _integer(params, "target_port", 1, 65535),
        "timeout_s": _integer(params, "timeout_s", 1, 600),
    }


def _start_artifact_mirror(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "job_id", "manifest_id")
    return {
        "status": "not_implemented",
        "job_id": _text(params, "job_id"),
        "manifest_id": _text(params, "manifest_id"),
    }


def _stop_artifact_mirror(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "job_id")
    return {"status": "not_implemented", "job_id": _text(params, "job_id")}


def _cancel_exec(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id", "request_id")
    return {
        "status": "not_implemented",
        "vm_id": _text(params, "vm_id"),
        "request_id": _text(params, "request_id"),
    }


def _destroy_vm(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "vm_id")
    return {"destroyed": True, "vm_id": _text(params, "vm_id")}


def _lock_network(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "job_id")
    return {"locked": True, "job_id": _text(params, "job_id"), "target_ports": []}


def _destroy_network(params: dict[str, Any]) -> dict[str, Any]:
    _require(params, "network_id")
    return {"destroyed": True, "network_id": _text(params, "network_id")}


HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "ping": _ping,
    "resolve_target": lambda p: {"target_id": resolve_target(_text(p, "target_id"))},
    "resolve_profile": lambda p: {"profile_id": resolve_profile(_text(p, "profile_id"))},
    "resolve_image": lambda p: {"image_id": resolve_image(_text(p, "image_id"))},
    "resolve_artifact": lambda p: {"artifact_id": resolve_artifact(_text(p, "artifact_id"))},
    "resolve_step": _step,
    "list_managed": _list_managed,
    "create_network": _create_network,
    "lock_network": _lock_network,
    "create_target": _create_target,
    "create_attacker": _create_attacker,
    "exec": _exec,
    "cancel_exec": _cancel_exec,
    "copy_in": _copy_in,
    "stage_artifact": _stage_artifact,
    "copy_out": _copy_out,
    "place_nonce": _place_nonce,
    "snapshot": _snapshot,
    "restore": _restore,
    "reboot": _reboot,
    "read_host_evidence": _read_host_evidence,
    "http_probe": _http_probe,
    "proxy_capture": _proxy_capture,
    "start_artifact_mirror": _start_artifact_mirror,
    "stop_artifact_mirror": _stop_artifact_mirror,
    "destroy_vm": _destroy_vm,
    "destroy_network": _destroy_network,
}


RUNTIME_VERBS = frozenset(
    {
        "ping",
        "create_network",
        "lock_network",
        "create_target",
        "create_attacker",
        "exec",
        "place_nonce",
        "copy_in",
        "stage_artifact",
        "copy_out",
        "http_probe",
        "proxy_capture",
        "read_host_evidence",
        "snapshot",
        "restore",
        "reboot",
        "destroy_vm",
        "destroy_network",
        "list_managed",
    }
)


def dispatch(request: dict[str, Any], runtime: Any = None) -> dict[str, Any]:
    verb = request.get("verb")
    if not isinstance(verb, str) or verb not in VERB_PARAMS:
        raise BrokerError("broker_registry_rejected", f"unknown verb: {verb!r}")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise BrokerError("broker_registry_rejected", "params must be an object")
    extra = set(params) - VERB_PARAMS[verb]
    if extra:
        raise BrokerError("broker_registry_rejected", f"unknown params: {sorted(extra)}")
    if runtime is not None and verb in RUNTIME_VERBS:
        return runtime.handle(verb, params)
    try:
        return HANDLERS[verb](params)
    except RegistryError as exc:
        raise BrokerError("broker_registry_rejected", str(exc)) from exc


def _journal_path(root: Path, job_id: str) -> Path:
    if not job_id:
        return root / "broker_calls.jsonl"
    if not JOB_ID_RE.fullmatch(job_id):
        raise BrokerError("broker_registry_rejected", "invalid job_id")
    return root / job_id / "broker_calls.jsonl"


def _append_journal(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _peer_uid(conn: socket.socket) -> int:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


class BrokerServer:
    """Small threaded Unix-socket server for the fixed broker verbs."""

    def __init__(
        self,
        socket_path: Path,
        journal_root: Path,
        allowed_uids: set[int] | None = None,
        runtime: Any = None,
    ) -> None:
        self.socket_path = socket_path
        self.journal_root = journal_root
        self.allowed_uids = allowed_uids or {os.getuid()}
        self.runtime = runtime
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        if self.socket_path.exists():
            if not stat.S_ISSOCK(self.socket_path.stat().st_mode):
                raise RuntimeError(f"refusing to replace non-socket: {self.socket_path}")
            self.socket_path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o660)
        sock.listen(16)
        sock.settimeout(0.2)
        self._socket = sock
        self._thread = threading.Thread(target=self._serve, name="xentry-broker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._socket is not None:
            self._socket.close()
        self.socket_path.unlink(missing_ok=True)

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            worker = threading.Thread(
                target=self._handle_connection,
                args=(conn,),
                name="xentry-broker-call",
                daemon=True,
            )
            worker.start()

    def _handle_connection(self, conn: socket.socket) -> None:
        with conn:
            try:
                self._handle(conn)
            except OSError:
                pass

    def _handle(self, conn: socket.socket) -> None:
        if _peer_uid(conn) not in self.allowed_uids:
            self._send(conn, {"ok": False, "error": {"code": "broker_unavailable", "message": "peer uid rejected"}})
            return
        try:
            request = self._read(conn)
        except BrokerError as exc:
            self._send(conn, {"ok": False, "error": {"code": exc.code, "message": str(exc)}})
            return
        started = _now_iso()
        verb = request.get("verb") if isinstance(request, dict) else None
        params = request.get("params", {}) if isinstance(request, dict) else {}
        status = "error"
        response: dict[str, Any]
        try:
            result = dispatch(request, self.runtime)
            response = {"ok": True, "result": result}
            status = "ok"
        except BrokerError as exc:
            response = {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
        except Exception as exc:  # noqa: BLE001 - the broker must answer every call
            response = {"ok": False, "error": {"code": "harness_error", "message": str(exc)}}
        job_id = str(request.get("job_id") or "") if isinstance(request, dict) else ""
        attempt_id = str(request.get("attempt_id") or "") if isinstance(request, dict) else ""
        seq = request.get("seq", 0) if isinstance(request, dict) else 0
        record = {
            "id": str(uuid.uuid4()),
            "job_id": job_id or "unknown",
            "attempt_id": attempt_id or "unknown",
            "seq": seq if isinstance(seq, int) else 0,
            "verb": verb if isinstance(verb, str) else "invalid",
            "params_sha256": _sha256_json(params),
            "started_at": started,
            "finished_at": _now_iso(),
            "status": status,
            "result_sha256": _sha256_json(response["result"]) if status == "ok" else None,
        }
        try:
            _append_journal(_journal_path(self.journal_root, job_id), record)
        except BrokerError as exc:
            response = {"ok": False, "error": {"code": exc.code, "message": str(exc)}}
        except OSError as exc:
            response = {"ok": False, "error": {"code": "broker_unavailable", "message": str(exc)}}
        response["call"] = record
        self._send(conn, response)

    @staticmethod
    def _read(conn: socket.socket) -> dict[str, Any]:
        data = bytearray()
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_REQUEST_BYTES:
                raise BrokerError("broker_registry_rejected", "request too large")
        if not data:
            raise BrokerError("broker_registry_rejected", "empty request")
        try:
            request = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrokerError("broker_registry_rejected", "invalid JSON request") from exc
        if not isinstance(request, dict):
            raise BrokerError("broker_registry_rejected", "request must be an object")
        return request

    @staticmethod
    def _send(conn: socket.socket, payload: dict[str, Any]) -> None:
        conn.sendall((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))


def _allowed_uids() -> set[int]:
    allowed = {0, os.getuid()}
    for name in ("xentry", os.environ.get("USER", "")):
        if not name:
            continue
        try:
            allowed.add(pwd.getpwnam(name).pw_uid)
        except KeyError:
            continue
    return allowed


def main() -> int:
    from broker.runtime import BrokerRuntime

    socket_path = Path(os.environ.get("XENTRY_BROKER_SOCKET", "/run/xentry/broker.sock"))
    data_dir = Path(os.environ.get("XENTRY_DATA_DIR", "/var/lib/xentry"))
    image_dir = Path(os.environ.get("XENTRY_IMAGE_DIR", "/var/lib/xentry/images"))
    runtime = BrokerRuntime(
        data_dir,
        image_dir,
        apply_nft=os.environ.get("XENTRY_APPLY_NFT", "1") != "0",
        qemu_user=os.environ.get("XENTRY_QEMU_USER") or None,
        manifest_path=Path(
            os.environ.get(
                "XENTRY_ARTIFACT_MANIFEST",
                "/var/lib/xentry/artifacts/manifest.json",
            )
        ),
        start_mirror=os.environ.get("XENTRY_START_MIRROR", "1") != "0",
        # Off by default: it is reachable from a guest during provisioning, so
        # it is opted into per deployment rather than assumed.
        start_apt_proxy=os.environ.get("XENTRY_START_APT_PROXY", "0") != "0",
        # Same reasoning, and the same default: reachable from a guest while it
        # provisions, so a deployment opts in.
        start_registry_proxy=os.environ.get("XENTRY_START_REGISTRY_PROXY", "0") != "0",
        # This line did not exist. BrokerRuntime took start_oci_mirror and
        # nothing ever passed it, so XENTRY_START_OCI_MIRROR was read nowhere
        # in the tree - while every Dockerfile job failed telling the operator
        # to set it, and setting it changed nothing no matter how often the
        # broker was restarted.
        start_oci_mirror=os.environ.get("XENTRY_START_OCI_MIRROR", "0") != "0",
    )
    server = BrokerServer(socket_path, data_dir / "jobs", _allowed_uids(), runtime=runtime)
    server.start()
    print(f"xentry broker listening on {socket_path}", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
