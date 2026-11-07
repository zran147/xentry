"""Broker step-manifest tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from broker.errors import BrokerError
from broker.steps import StepRegistry

ROOT = Path(__file__).resolve().parents[1]


def _make_manifest(tmp_path: Path, script_text: str = "#!/bin/bash\nexit 0\n") -> tuple[Path, Path]:
    targets = tmp_path / "targets"
    script = targets / "demo" / "run.sh"
    script.parent.mkdir(parents=True)
    script.write_text(script_text, encoding="utf-8")
    manifest = tmp_path / "steps.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "steps": {
                    "demo-step": {
                        "user": "xentry-guest",
                        "script": "demo/run.sh",
                        "sha256": hashlib.sha256(script_text.encode()).hexdigest(),
                        "timeout_s": 60,
                        "params": ["value"],
                        "required": ["value"],
                        "tty": False,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return manifest, targets


def test_step_registry_loads_and_validates_params(tmp_path: Path) -> None:
    manifest, targets = _make_manifest(tmp_path)
    registry = StepRegistry(manifest, targets)
    spec = registry.get("demo-step")
    assert spec.user == "xentry-guest"
    assert registry.validate_params(spec, {"value": "ok"}) == ["ok"]
    with pytest.raises(BrokerError) as exc:
        registry.validate_params(spec, {"value": "ok", "extra": "no"})
    assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError) as exc:
        registry.validate_params(spec, {})
    assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError) as exc:
        registry.get("unknown-step")
    assert exc.value.code == "broker_registry_rejected"


def test_step_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    manifest, targets = _make_manifest(tmp_path)
    (targets / "demo/run.sh").write_text("#!/bin/bash\nexit 1\n", encoding="utf-8")
    with pytest.raises(BrokerError) as exc:
        StepRegistry(manifest, targets)
    assert exc.value.code == "artifact_hash_mismatch"


def test_step_script_cannot_escape_targets(tmp_path: Path) -> None:
    manifest, targets = _make_manifest(tmp_path)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["steps"]["demo-step"]["script"] = "../escape.sh"
    manifest.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(BrokerError) as exc:
        StepRegistry(manifest, targets)
    assert exc.value.code == "preflight_refused"


def test_real_manifest_has_gitlab_prefix_step() -> None:
    registry = StepRegistry(ROOT / "targets/steps.yaml", ROOT / "targets")
    spec = registry.get("prefix-gitlab-nonce")
    assert spec.user == "root"
    assert spec.timeout_s == 30
    assert "nonce_path" in spec.params
