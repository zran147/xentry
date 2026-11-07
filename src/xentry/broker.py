"""Fixed-verb Unix-socket client for the root broker."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any


class BrokerError(RuntimeError):
    """A broker call failed or was rejected."""

    def __init__(self, code: str, message: str, call: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.call = call


class BrokerClient:
    """One request per connection; the broker owns all id resolution."""

    def __init__(self, socket_path: str | Path | None = None, timeout: float = 30.0):
        default = os.environ.get("XENTRY_BROKER_SOCKET", "/run/xentry/broker.sock")
        self.socket_path = Path(socket_path or default)
        self.timeout = timeout
        self.last_call: dict[str, Any] | None = None

    def call(
        self,
        verb: str,
        params: dict[str, Any] | None = None,
        *,
        job_id: str = "",
        attempt_id: str = "",
        seq: int = 0,
    ) -> Any:
        request = {
            "verb": verb,
            "params": params or {},
            "job_id": job_id,
            "attempt_id": attempt_id,
            "seq": seq,
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(str(self.socket_path))
                sock.sendall((json.dumps(request, sort_keys=True) + "\n").encode("utf-8"))
                data = bytearray()
                while not data.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
        except OSError as exc:
            raise BrokerError("broker_unavailable", str(exc)) from exc
        if not data:
            raise BrokerError("broker_unavailable", "empty broker response")
        try:
            response = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrokerError("broker_unavailable", "invalid broker response") from exc
        if not isinstance(response, dict) or not response.get("ok"):
            error = response.get("error", {}) if isinstance(response, dict) else {}
            call = response.get("call") if isinstance(response, dict) else None
            self.last_call = call if isinstance(call, dict) else None
            raise BrokerError(
                str(error.get("code", "broker_unavailable")),
                str(error.get("message", "broker error")),
                self.last_call,
            )
        call = response.get("call")
        self.last_call = call if isinstance(call, dict) else None
        return response.get("result")

    def ping(self) -> dict[str, Any]:
        return self.call("ping")

    def resolve_artifact(self, artifact_id: str) -> dict[str, Any]:
        return self.call("resolve_artifact", {"artifact_id": artifact_id})

    def destroy_vm(self, vm_id: str) -> dict[str, Any]:
        return self.call("destroy_vm", {"vm_id": vm_id})

    def destroy_network(self, network_id: str) -> dict[str, Any]:
        return self.call("destroy_network", {"network_id": network_id})
