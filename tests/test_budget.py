"""Budget and dependency guard for the Phase 0 skeleton."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOTS = ("src", "broker", "scripts")
MODULE_CAP = 53
# A NOTE ON HOW THESE RAISES ARE ASKED FOR, added 2026-11-18 at the user's
# instruction. When a change does not fit, say how many lines it needs and
# stop. Do not pack signatures, collapse dict literals or move docstrings into
# comments to satisfy the counter: comments and blank lines are free, so
# formatting is an easy way to make an overrun invisible, and cramped code is
# where most of this project's bugs have come from. The harness wiring was
# written, measured at 108 against 53 available, and reverted rather than
# squeezed - that was right; the rounds of column-packing before it were not.
#
# 14,654 -> 14,699 -> 14,769 -> 14,949 -> 15,019 -> 15,069 -> 15,179 and the
# module cap 52 -> 53 on
# 2026-11-18, for harness mode: ADR 0003 (the model provisions the target) and
# ADR 0004 (free_exec and the tool surface). Each of the three line raises was
# asked for and granted separately, against a staged estimate the ADR records:
# 45 for the switch and the kind, 70 for the broker gate, 180 for the tool
# layer and the verification. The module cap moved with the third because that
# stage is two new modules - src/xentry/harness.py, the tool layer that is the
# trust boundary, and src/xentry/statediff.py, the comparison that decides
# whether a generated script rebuilt what the model explored.
#
# They are two files rather than one on purpose. statediff imports nothing but
# __future__ and typing, and a test asserts that by walking its AST: a module
# that cannot read a machine cannot be fooled into reporting on the wrong one.
# Folding it into harness.py, which needs dataclasses, would have cost that
# proof to save a module.
#
# Raised twice on 2026-11-14, which is the explicit budget change gate G14
# asks for; ADR entries 28a and 30a record both. 12,400 -> 12,600 paid for the
# PoC's recursive file tree as evidence and for placing an approved file where
# its kind belongs, after 25 lines came back from dead code. 12,600 -> 12,700
# pays for attacker provisioning and the command-only PoC. 12,700 -> 12,800
# pays for the approval card offering the PoC's own file, which is what two
# bugs in entry 32 left the operator doing by hand. 12,800 -> 13,000 and the
# module cap 50 -> 51 were approved for the OCI mirror. Every one of these was
# asked for; none was taken on initiative.
#
# 13,000 -> 13,100 pays for the OCI mirror, which measured 232 counted lines
# against the 130 estimated: docstrings count here. The module's own "why this
# exists" prose moved into ADR entry 34 rather than being deleted - the ADR is
# where the design record belongs, and keeping it in both places was the
# duplication, not the explanation.
#
# 13,100 -> 13,200 for two defect fixes the operator approved: the suggested
# .deb as an archive path rather than snapshot's /file/<sha1>, which has no
# suffix and so was refused by the endpoint that offered it; and treating a
# file from the PoC's own repository as needing no approval - entry 35.
#
# 13,200 -> 13,600 and the module cap 51 -> 53 were set for a debugging
# session, then trimmed to 13,350 and 52 once that session's findings were in
# and the room they actually needed was known. Entry 37 spent 44 of it: the
# per-check transcript, the PoC's own source files as evidence, value-ordered
# versions, the nginx placement. One spare module and 62 lines remain.
LINE_CAP = 15_241


def python_files() -> list[Path]:
    files: list[Path] = []
    for root in PYTHON_ROOTS:
        files.extend((ROOT / root).rglob("*.py"))
    return sorted(files)


def test_module_cap() -> None:
    files = python_files()
    assert len(files) <= MODULE_CAP, f"{len(files)} Python modules exceeds {MODULE_CAP}"


def test_line_cap() -> None:
    total = 0
    for path in python_files():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                total += 1
    assert total <= LINE_CAP, f"{total} handwritten lines exceeds {LINE_CAP}"


def test_python_version_pin() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["requires-python"] == ">=3.12,<3.13"


def test_no_container_runtime_dependency() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = " ".join(data["project"].get("dependencies", [])).lower()
    assert "docker" not in deps
    assert "podman" not in deps


def test_no_env_default_is_a_relative_path() -> None:
    """A relative default resolves against the working directory, not the tree.

    .env.example shipped ./var/artifacts, ./var/images, ./targets and
    ./config/*.yaml. install.sh normalised some keys and missed three, so a
    deployed host read artifacts from /opt/xentry/var/artifacts while its
    manifest said /var/lib/xentry/artifacts/manifest.json - two directories,
    1.1G in the one nothing consulted, and a backup that could easily have been
    taken of the wrong one.

    The app and the broker run with different working directories, so the same
    relative value means different things to each. Absolute only.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for name in (".env.example",):
        path = root / name
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            value = stripped.split("=", 1)[1].strip()
            if re.match(r"^\.{1,2}/", value):
                offenders.append(f"{name}:{number}: {stripped}")
    assert not offenders, "relative path defaults: " + ", ".join(offenders)
