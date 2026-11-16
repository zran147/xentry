"""The attacker image's pinned Python wheels.

A PoC's own imports are not a per-job resolution: the attacker VM has no
network once the job locks it, so what a PoC can import is decided when the
image is built. CVE-2026-56290's PoC needs `requests` and `colorama` and the
image carried only the first.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WHEEL = {"url": "https://files.pythonhosted.org/x/colorama-0.4.6.whl", "sha256": "ab" * 32}


def _build_images() -> Any:
    spec = importlib.util.spec_from_file_location("bi", ROOT / "scripts" / "build-images.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifests() -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "config" / "image-manifests.yaml").read_text())
    images = data.get("images") or data
    assert isinstance(images, dict)
    return images


def test_the_attacker_image_pins_what_a_poc_imports() -> None:
    attacker = _manifests()["ubuntu-24.04-attacker"]
    names = {entry["url"].rsplit("/", 1)[-1].split("-")[0].lower() for entry in attacker["wheels"]}
    assert {"requests", "colorama"} <= names
    for entry in attacker["wheels"]:
        assert entry["url"].startswith("https://files.pythonhosted.org/")
        assert len(entry["sha256"]) == 64


def test_requests_has_exactly_one_source() -> None:
    """apt's python3-requests and a pinned wheel would be two, installed over
    each other in an order nothing states."""
    attacker = _manifests()["ubuntu-24.04-attacker"]
    assert "python3-requests" not in attacker["packages"]
    assert "python3-pip" in attacker["packages"]


def test_every_wheel_is_installed_under_require_hashes() -> None:
    """pip checks the digests itself, so a wheel that does not match fails the
    build rather than reaching an attacker VM."""
    command = _build_images().wheel_commands([WHEEL])
    assert "--require-hashes" in command
    assert "--no-deps" in command
    assert f"--hash=sha256:{WHEEL['sha256']}" in command
    assert WHEEL["url"] in command


def test_an_image_with_no_wheels_adds_no_step() -> None:
    assert _build_images().wheel_commands([]) == ""


def test_the_requirements_heredoc_survives_cloud_init() -> None:
    """runcmd is YAML, and the requirements file is written by a heredoc: a
    quoting change here would silently produce an image with no wheels."""
    command = _build_images().wheel_commands([WHEEL, dict(WHEEL, sha256="cd" * 32)])
    document = yaml.safe_dump({"runcmd": [["bash", "-lc", command]]}, sort_keys=False)
    assert yaml.safe_load(document)["runcmd"][0][2] == command
    # And the heredoc itself writes both lines, with no shell expansion.
    probe = command.replace("pip3 install", "cat /tmp/xentry-wheels.txt; : ")
    done = subprocess.run(
        ["bash", "-lc", probe], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.count("--hash=sha256:") == 2


def test_a_wheel_without_a_digest_or_over_http_is_refused() -> None:
    module = _build_images()
    manifests = {
        "images": {
            "bad": {
                "base_artifact": "ubuntu-base-image",
                "packages": ["curl"],
                "wheels": [{"url": "http://x/y.whl", "sha256": "short"}],
            }
        }
    }
    base = {
        "artifacts": {
            "ubuntu-base-image": {
                "kind": "image",
                "status": "resolved",
                "url": "https://example.com/base.img",
                "sha256": "0" * 64,
            }
        }
    }
    errors = module.validate(manifests, base)
    assert any("no https url" in error for error in errors)
    assert any("no sha256" in error for error in errors)
