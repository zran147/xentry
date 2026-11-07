"""Cloud-init actor separation checks."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from broker.runtime import BrokerRuntime


@pytest.mark.skipif(shutil.which("cloud-localds") is None, reason="cloud-localds is missing")
def test_cloud_init_separates_root_and_actor(tmp_path: Path) -> None:
    runtime = BrokerRuntime(tmp_path / "data", tmp_path / "images")
    seed = runtime._seed(
        "job-1",
        "target",
        "ssh-ed25519 ROOTKEY",
        "ssh-ed25519 ACTORKEY",
        "target_create_failed",
    )
    user_data = yaml.safe_load(
        (seed.parent / "user-data.yaml").read_text(encoding="utf-8").removeprefix("#cloud-config\n")
    )
    users = {entry["name"]: entry for entry in user_data["users"]}
    assert users["root"]["ssh_authorized_keys"] == ["ssh-ed25519 ROOTKEY"]
    assert users["xentry-guest"]["ssh_authorized_keys"] == ["ssh-ed25519 ACTORKEY"]
    assert users["xentry-guest"]["sudo"] is False
    assert "sudo" not in users["root"]
    assert user_data["ssh_pwauth"] is False
