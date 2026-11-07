"""Target instance tests."""

from __future__ import annotations

import pytest

from xentry.targets import TARGETS, artifact_hash, by_cve, by_poc_url, setup_script_path


def test_three_targets_and_lookup() -> None:
    assert set(TARGETS) == {"php2shell", "gitlab", "dirtyfrag"}
    assert by_cve("CVE-2026-109618") is TARGETS["php2shell"]
    assert by_cve("CVE-2026-85706") is TARGETS["gitlab"]
    assert by_cve("CVE-2026-43500") is TARGETS["dirtyfrag"]
    assert by_cve("CVE-1999-0001") is None
    assert by_poc_url("https://github.com/V4bel/dirtyfrag.git") is TARGETS["dirtyfrag"]
    assert by_poc_url("https://example.com/poc") is None


def test_one_decisive_probe_per_target() -> None:
    for target in TARGETS.values():
        probe = target.decisive_probe()
        assert probe.decisive is True


def test_setup_scripts_and_poc_pins_are_resolved() -> None:
    for target in TARGETS.values():
        script = setup_script_path(target)
        assert script.is_file()
        assert target.setup_sha256
        assert artifact_hash(target.poc.artifact_id) == target.poc.sha256


def test_php_setup_keeps_the_poc_required_php_defaults() -> None:
    script = setup_script_path(TARGETS["php2shell"]).read_text(encoding="utf-8")
    assert "cp php.ini-production" not in script
    assert "zend_extension=opcache" in script
    assert "max_multipart_body_parts" in script


def test_remote_targets_have_attackers_and_dirtyfrag_has_kernel() -> None:
    for target_id in ("php2shell", "gitlab"):
        target = TARGETS[target_id]
        assert target.attacker_profile_id == "attacker-remote"
        assert target.kernel_artifact_id is None
    dirty = TARGETS["dirtyfrag"]
    assert dirty.attacker_profile_id is None
    assert dirty.kernel_artifact_id == "kernel-6.17.0-23"
    with pytest.raises(RuntimeError):
        # A malformed target with two decisive probes is not accepted.
        from dataclasses import replace

        replace(
            dirty,
            probes=dirty.probes + dirty.probes,
        ).decisive_probe()
