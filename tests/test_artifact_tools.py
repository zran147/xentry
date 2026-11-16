"""Tests for the artifact research/pin helpers."""

from __future__ import annotations

import stat
import subprocess
import sys
from pathlib import Path

import pytest

from xentry.artifact_tools import (
    extract_hashes,
    extract_urls,
    load_catalog,
    parse_deb822,
    parse_sha256sums,
    validate_sha256,
    write_catalog,
)


def test_validate_sha256() -> None:
    digest = "a" * 64
    assert validate_sha256(digest) == digest
    with pytest.raises(ValueError):
        validate_sha256("A" * 64)
    with pytest.raises(ValueError):
        validate_sha256("short")


def test_parse_sha256sums() -> None:
    text = "\n".join(
        [
            "b" * 64 + "  ubuntu-24.04-server-cloudimg-amd64.img",
            "# comment",
            "not-a-hash  other.iso",
        ]
    )
    assert parse_sha256sums(text) == {"ubuntu-24.04-server-cloudimg-amd64.img": "b" * 64}


def test_extract_hashes_and_urls() -> None:
    text = "sha256: " + "c" * 64 + " url https://example.com/a.deb"
    assert extract_hashes(text) == ["c" * 64]
    assert extract_urls(text) == ["https://example.com/a.deb"]


def test_parse_deb822() -> None:
    text = (
        "Package: example\n"
        "Version: 1.0\n"
        "Description: first line\n"
        " continued line\n"
        "\n"
        "Package: other\n"
        "Version: 2.0\n"
    )
    entries = parse_deb822(text)
    assert len(entries) == 2
    assert entries[0]["Package"] == "example"
    assert entries[0]["Version"] == "1.0"
    assert entries[1]["Package"] == "other"


# ------------------------------------------------- pin-artifact, the writer ---


def _pin(catalog: Path, *args: str) -> subprocess.CompletedProcess[str]:
    import subprocess

    root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [sys.executable, str(root / "scripts/pin-artifact.py"), "--catalog", str(catalog), *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
        env={"PYTHONPATH": str(root / "src"), "PATH": "/usr/bin:/bin"},
    )


SHA = "c" * 64


def test_a_new_build_artifact_can_be_pinned_in_one_reviewed_step(tmp_path: Path) -> None:
    """A new image had to be added as an unresolved entry and pinned after,
    which left the catalog failing Gate G in between. --kind closes that gap."""
    import yaml

    catalog = tmp_path / "artifacts.yaml"
    catalog.write_text(yaml.safe_dump({"version": 1, "artifacts": {}}), encoding="utf-8")
    done = _pin(
        catalog,
        "--artifact",
        "ubuntu-example-image",
        "--kind",
        "image",
        "--url",
        "build://ubuntu-base-image+example",
        "--sha256",
        SHA,
        "--source",
        "scripts/build-images.py",
        "--accept",
    )
    assert done.returncode == 0, done.stdout + done.stderr
    entry = yaml.safe_load(catalog.read_text())["artifacts"]["ubuntu-example-image"]
    assert entry["status"] == "resolved"
    assert entry["sha256"] == SHA
    assert entry["kind"] == "image"


def test_creating_an_entry_needs_the_kind_and_the_acceptance(tmp_path: Path) -> None:
    import yaml

    catalog = tmp_path / "artifacts.yaml"
    catalog.write_text(yaml.safe_dump({"version": 1, "artifacts": {}}), encoding="utf-8")
    common = ["--artifact", "typo-image", "--url", "build://x", "--sha256", SHA, "--source", "s"]
    # Without --kind a mistyped name would add a second entry rather than
    # correct the first.
    missing_kind = _pin(catalog, *common, "--accept")
    assert missing_kind.returncode == 2
    assert "pass --kind" in missing_kind.stderr
    # And the review gate still applies to a creation.
    unaccepted = _pin(catalog, *common, "--kind", "image")
    assert unaccepted.returncode == 2
    assert "--accept" in unaccepted.stderr
    assert yaml.safe_load(catalog.read_text())["artifacts"] == {}


def test_a_new_artifact_still_needs_a_url(tmp_path: Path) -> None:
    import yaml

    catalog = tmp_path / "artifacts.yaml"
    catalog.write_text(yaml.safe_dump({"version": 1, "artifacts": {}}), encoding="utf-8")
    done = _pin(
        catalog,
        "--artifact",
        "nameless",
        "--kind",
        "image",
        "--sha256",
        SHA,
        "--source",
        "s",
        "--accept",
    )
    assert done.returncode == 2
    assert "needs --url" in done.stderr


def test_a_rewritten_catalog_stays_readable_by_the_unprivileged_app(tmp_path: Path) -> None:
    """The app reads the catalog at import time, as a user that is not root.

    mkstemp makes the temp file 0600 and replace() carries that mode onto the
    target, so an atomic rewrite used to leave the catalog unreadable and the
    web app would not import at all.
    """
    catalog = tmp_path / "artifacts.yaml"
    write_catalog(catalog, {"artifacts": {"poc-x": {"kind": "poc"}}})
    assert stat.S_IMODE(catalog.stat().st_mode) == 0o644

    catalog.chmod(0o600)
    write_catalog(catalog, {"artifacts": {"poc-x": {"kind": "poc"}, "poc-y": {"kind": "poc"}}})
    assert stat.S_IMODE(catalog.stat().st_mode) == 0o644
    assert set(load_catalog(catalog)["artifacts"]) == {"poc-x", "poc-y"}
