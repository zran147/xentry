"""Provisioning the attacker, in the one window it has.

The attacker image is built with a package list, digest-pinned wheels and
digest-pinned tarballs, so a PoC needing anything else failed - and it could
not be fixed at job time, because lock_network takes the attacker's network
away before any PoC code runs. CVE-2021-44228's PoC runs an LDAP server with
java and the image has no JDK at all.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.test_generic_target import _facts, _run
from xentry.db import connect
from xentry.jobstore import list_steps


def _steps(conn: Any, job_id: str) -> list[str]:
    return [row["name"] for row in list_steps(conn, job_id)]


def test_the_attacker_is_provisioned_before_its_network_closes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Order is the whole point: after the VM exists, before lock_network."""
    job_id, _dir, _broker = _run(
        tmp_path, _facts(attacker_packages=["openjdk-11-jdk"]), monkeypatch
    )
    conn = connect(tmp_path / "xentry.db")
    try:
        names = _steps(conn, job_id)
    finally:
        conn.close()
    assert "setup_attacker" in names, names
    assert names.index("create_attacker") < names.index("setup_attacker")
    assert names.index("setup_attacker") < names.index("lock_network")


def test_it_installs_from_the_attackers_own_archive_not_the_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The target's proxy serves one archive at one serial - Debian sid at
    20211004 for a 2021 advisory. Pointing Ubuntu noble at that would ask apt
    to install Debian packages onto Ubuntu."""
    _job, _dir, broker = _run(
        tmp_path, _facts(attacker_packages=["openjdk-11-jdk"]), monkeypatch
    )
    params = broker.exec_params["setup-attacker"]
    assert params["packages"] == "openjdk-11-jdk"
    assert params["archive"] == "ubuntu"
    assert params["suite"] == "noble"
    assert params["apt_proxy_url"] == "http://10.42.1.1:8084"
    # And emphatically not the target's proxy.
    assert params["apt_proxy_url"] != broker.exec_params["setup-generic"]["apt_proxy_url"]


def test_no_packages_means_no_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plain Python PoC needs nothing: the image already carries its wheels."""
    job_id, _dir, broker = _run(tmp_path, _facts(), monkeypatch)
    conn = connect(tmp_path / "xentry.db")
    try:
        names = _steps(conn, job_id)
    finally:
        conn.close()
    assert "setup_attacker" not in names, names
    assert "setup-attacker" not in broker.exec_params
    # And the steps after it keep their sequence numbers.
    assert names.index("create_attacker") < names.index("lock_network")


def test_the_suite_the_runner_asks_for_is_the_attacker_images_own() -> None:
    """Two tables that must agree.

    The runner names the attacker's suite as a literal, and the attacker image
    id carries its Ubuntu version. Move the image to a newer Ubuntu and leave
    the literal alone and apt would be pointed at the wrong suite's indexes -
    which either installs the wrong packages or refuses, and refusing is the
    luckier outcome. Tied to release.RELEASES because that is the table that
    maps a version to a suite.
    """
    from xentry import release
    from xentry.runner import ATTACKER_IMAGE, ATTACKER_SUITE

    versions = {item.version: item.suite for item in release.RELEASES}
    named = [
        suite for version, suite in versions.items() if version in ATTACKER_IMAGE
    ]
    assert named == [ATTACKER_SUITE], (
        f"{ATTACKER_IMAGE} is not the {ATTACKER_SUITE} image: {named}"
    )


def test_the_step_is_in_both_allowlists_and_reuses_the_generic_script() -> None:
    """A step the manifest describes and the broker's own set omits is refused
    as "unknown step id" at the first call, which is how every derived job
    died once before."""
    import hashlib

    import yaml

    from broker.registry import STEPS, resolve_step

    root = Path(__file__).resolve().parents[1]
    steps = yaml.safe_load((root / "targets/steps.yaml").read_text())["steps"]
    spec = steps["setup-attacker"]
    assert "setup-attacker" in STEPS
    resolved = resolve_step("setup-attacker")
    assert resolved.step_id == "setup-attacker"
    # root, because configuring apt and installing packages needs it. The
    # broker enforces the user; the app never supplies one.
    assert resolved.allowed_users == ("root",)
    # The same script as the target's, so the attacker inherits one vocabulary
    # rather than getting a second one to keep in step.
    assert spec["script"] == steps["setup-generic"]["script"]
    assert spec["params"] == steps["setup-generic"]["params"]
    script = root / "targets" / spec["script"]
    assert hashlib.sha256(script.read_bytes()).hexdigest() == spec["sha256"]


def test_every_step_script_hash_in_the_manifest_is_current() -> None:
    """A stale sha256 in steps.yaml makes the broker refuse the step.

    The hashes are enforced (broker/steps.py reads the expected digest), so
    editing a step script without updating the manifest turns into a refusal
    at the moment the step runs. This recomputes every one, so the edit and
    the manifest cannot drift apart.
    """
    import hashlib
    import pathlib
    import re

    # The REPO, not /opt/xentry-broker: these assert what we are about to
    # ship, so they must pass before an install, not after it.
    root = pathlib.Path(__file__).resolve().parents[1]
    manifest = root / "targets/steps.yaml"

    text = manifest.read_text()
    pairs = re.findall(
        r"script:\s*(\S+)\s*\n\s*sha256:\s*([0-9a-f]{64})", text
    )
    assert pairs, "no script/sha256 pairs found - has the format changed?"

    stale = []
    for rel, expected in pairs:
        path = root / "targets" / rel
        if not path.exists():
            stale.append(f"{rel}: missing")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            stale.append(f"{rel}: manifest {expected[:12]}, file {actual[:12]}")
    assert not stale, "steps.yaml is out of date:\n  " + "\n  ".join(stale)


def test_apt_waits_long_enough_for_a_cold_proxy_cache() -> None:
    """60s was not enough for a first fetch through the mirror VM.

    A cold cache against a snapshot host is slow: the first fetch of a large
    index exceeded a minute, apt broke the pipe, and the mirror logged
    BrokenPipeError while still completing the fetch. The retry hit the warm
    cache and succeeded - so it recovered by luck, twice, 73 seconds apart,
    and only because Acquire::Retries is 3.
    """
    import pathlib

    script = (
        pathlib.Path(__file__).resolve().parents[1]
        / "targets/common/setup-generic.sh"
    )
    text = script.read_text()
    assert 'Acquire::http::Timeout "300";' in text
    assert 'Acquire::Retries "3";' in text
