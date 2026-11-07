"""Budget and dependency guard for the Phase 0 skeleton."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOTS = ("src", "broker", "scripts")
MODULE_CAP = 44
LINE_CAP = 8_000


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
