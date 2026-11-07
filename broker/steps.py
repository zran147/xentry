"""Broker-owned step command registry.

The manifest binds a step id to a checked-in script, an allowed guest user, a
timeout, and typed positional parameters. The broker verifies every script hash
at load time; the app never supplies a command, path, or user.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from broker.errors import BrokerError


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class StepSpec:
    step_id: str
    user: str
    script: str
    sha256: str
    timeout_s: int
    params: tuple[str, ...]
    required: tuple[str, ...]
    tty: bool = False

    def local_path(self, targets_dir: Path) -> Path:
        return targets_dir / self.script


class StepRegistry:
    def __init__(self, manifest_path: Path, targets_dir: Path) -> None:
        self.manifest_path = manifest_path
        self.targets_dir = targets_dir
        self.steps = self._load()

    def _load(self) -> dict[str, StepSpec]:
        if not self.manifest_path.exists():
            raise BrokerError("preflight_refused", f"missing step manifest: {self.manifest_path}")
        data = yaml.safe_load(self.manifest_path.read_text(encoding="utf-8")) or {}
        raw_steps = data.get("steps")
        if not isinstance(raw_steps, dict) or not raw_steps:
            raise BrokerError("preflight_refused", "step manifest has no steps")
        base = self.targets_dir.resolve()
        steps: dict[str, StepSpec] = {}
        for step_id, raw in raw_steps.items():
            if not isinstance(raw, dict):
                raise BrokerError("preflight_refused", f"invalid step spec: {step_id}")
            user = str(raw.get("user", ""))
            if user not in {"root", "xentry-guest"}:
                raise BrokerError("preflight_refused", f"invalid step user: {step_id}")
            script = str(raw.get("script", ""))
            if not script:
                raise BrokerError("preflight_refused", f"missing step script: {step_id}")
            path = (self.targets_dir / script).resolve()
            try:
                path.relative_to(base)
            except ValueError as exc:
                raise BrokerError("preflight_refused", f"step script escapes targets: {step_id}") from exc
            if not path.is_file():
                raise BrokerError("preflight_refused", f"missing step script: {path}")
            expected = str(raw.get("sha256", ""))
            actual = _sha256(path)
            if actual != expected:
                raise BrokerError(
                    "artifact_hash_mismatch",
                    f"step script hash mismatch: {step_id}",
                )
            params = tuple(str(item) for item in raw.get("params") or ())
            required = tuple(str(item) for item in raw.get("required") or ())
            if not set(required).issubset(params):
                raise BrokerError("preflight_refused", f"required params not declared: {step_id}")
            steps[step_id] = StepSpec(
                step_id=step_id,
                user=user,
                script=script,
                sha256=expected,
                timeout_s=int(raw.get("timeout_s", 600)),
                params=params,
                required=required,
                tty=bool(raw.get("tty", False)),
            )
        return steps

    def get(self, step_id: str) -> StepSpec:
        try:
            return self.steps[step_id]
        except KeyError as exc:
            raise BrokerError("broker_registry_rejected", f"unknown step id: {step_id}") from exc

    def validate_params(self, spec: StepSpec, params: dict[str, Any]) -> list[str]:
        extra = set(params) - set(spec.params)
        if extra:
            raise BrokerError("broker_registry_rejected", f"unknown step params: {sorted(extra)}")
        missing = [name for name in spec.required if name not in params]
        if missing:
            raise BrokerError("broker_registry_rejected", f"missing step params: {missing}")
        values: list[str] = []
        for name in spec.params:
            value = params.get(name, "")
            if not isinstance(value, str) or len(value) > 2048:
                raise BrokerError("broker_registry_rejected", f"invalid step param: {name}")
            values.append(value)
        return values
