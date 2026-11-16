"""Target instance tests."""

from __future__ import annotations

import pytest

from xentry.targets import (
    TARGETS,
    artifact_hash,
    by_cve,
    by_poc_url,
    setup_script_path,
)


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


def test_a_repin_reaches_a_running_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """TARGETS was built at import, with the digests of its three targets.

    So re-pinning one, or editing a checked-in script, left a running app
    serving the old digest and a job failing "artifact hash mismatch" until
    someone restarted it - the broker's bug from entry 49b, in the app. The
    dict is mutated rather than replaced, because callers hold a reference
    from `from xentry.targets import TARGETS`.
    """
    import os

    from xentry import targets as mod

    held = mod.TARGETS  # as app.py held it before by_id existed
    before = mod.by_cve("CVE-2026-109618")
    assert before is not None
    first = before.setup_sha256

    calls: list[int] = []
    real = mod._build_targets

    def counted() -> dict:
        calls.append(1)
        built = real()
        # Pretend the operator re-pinned: a different setup hash.
        import dataclasses

        php = built["php2shell"]
        built["php2shell"] = dataclasses.replace(php, setup_sha256="f" * 64)
        return built

    monkeypatch.setattr(mod, "_build_targets", counted)

    # Nothing changed on disk: no rebuild, and the same answer.
    assert mod.by_cve("CVE-2026-109618").setup_sha256 == first
    assert not calls

    # The manifest is rewritten, as pin-artifact.py and a script edit do.
    stamp = mod.STEPS.stat().st_mtime_ns + 1_000_000_000
    os.utime(mod.STEPS, ns=(stamp, stamp))
    after = mod.by_cve("CVE-2026-109618")
    assert after is not None
    assert after.setup_sha256 == "f" * 64
    assert len(calls) == 1
    # And the object app.py imported sees it, because it is the same dict.
    assert held["php2shell"].setup_sha256 == "f" * 64
    # by_id and by_poc_url go through the same refresh.
    assert mod.by_id("php2shell") is not None
    assert mod.by_poc_url(after.poc.repository) is not None
