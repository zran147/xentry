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


def test_the_wheel_install_does_not_try_to_uninstall_an_apt_package() -> None:
    """--ignore-installed, or the attacker image cannot be built at all.

    The base image carries python3-urllib3 from apt. The pinned wheel list also
    carries urllib3, so pip tried to replace the dpkg copy and refused:

        ERROR: Cannot uninstall urllib3 2.0.7, RECORD file not found.
        Hint: The package was installed by debian.

    A dpkg-installed package has no RECORD file, so pip cannot uninstall it.
    Under `set -euo pipefail` that killed the build 108 seconds in, after the
    other seven images had already succeeded - the attacker image is the only
    one that installs wheels.

    --ignore-installed installs over it instead, which is what this list means
    anyway: pip's /usr/local/lib/python3/dist-packages precedes apt's
    /usr/lib/python3/dist-packages on sys.path, so the pinned wheel is the one
    a PoC imports. --require-hashes still enforces every digest.
    """
    import importlib.util
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "build_images_probe", root / "scripts/build-images.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    rendered = module.wheel_commands(
        [{"url": "https://example.invalid/urllib3-2.5.0-py3-none-any.whl",
          "sha256": "ab" * 32}]
    )
    pip_line = next(l for l in rendered.splitlines() if l.startswith("pip3 install"))
    assert "--ignore-installed" in pip_line, pip_line
    # The digest check is the reason this list exists; it must not be traded away.
    assert "--require-hashes" in pip_line, pip_line
    assert "--no-deps" in pip_line, pip_line


def test_the_image_build_can_be_pointed_at_an_apt_mirror() -> None:
    """archive.ubuntu.com answering one request in two stalls every build.

    Each image runs apt-get update inside itself against the base image's own
    sources. When Canonical throttles, seven builds crawl for ten minutes each.
    XENTRY_APT_MIRROR rewrites the guest's sources first.

    sed -E and @ as the delimiter both matter: `?` is literal in a basic regex
    so `https?://` matched nothing, and a `|` delimiter is closed by the `|`
    inside the host alternation.
    """
    import pathlib

    text = (
        pathlib.Path(__file__).resolve().parents[1] / "scripts/build-images.py"
    ).read_text()
    code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
    assert 'os.environ.get("XENTRY_APT_MIRROR"' in code
    assert "sed -Ei" in code, "a basic regex cannot match https?://"
    assert "sed -Ei 's@" in code, "a | delimiter is closed by the alternation"


def test_an_image_already_built_and_verified_is_not_rebuilt() -> None:
    """Every image booted a VM and ran apt in it, every time install.sh ran.

    Eight images at roughly ten minutes each is an hour added to any re-run,
    whatever changed - and against a degraded archive one of the eight would
    usually fail and take the install with it. Nothing checked whether the
    image was already there: only the base image DOWNLOAD was skipped.

    The digest is what makes the skip safe. A path check alone would keep a
    half-written qcow2 from an interrupted build, and a CVE reproduced against
    an image nobody can account for is worse than an hour lost.
    """
    import hashlib
    import importlib.util
    import json
    import pathlib
    import tempfile

    root = pathlib.Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "build_images_skip", root / "scripts/build-images.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with tempfile.TemporaryDirectory() as raw:
        images = pathlib.Path(raw)
        image = images / "ubuntu-24.04-target.qcow2"
        image.write_bytes(b"pretend qcow2")
        report = images / "build-results.json"
        digest = hashlib.sha256(image.read_bytes()).hexdigest()
        report.write_text(json.dumps({"images": {"ubuntu-24.04-target": {"sha256": digest}}}))

        assert module.already_built(report, "ubuntu-24.04-target", images)

        # The bytes changed under a digest that still says otherwise.
        image.write_bytes(b"an interrupted build")
        assert not module.already_built(report, "ubuntu-24.04-target", images)

        # Present, but never recorded.
        image.write_bytes(b"pretend qcow2")
        report.write_text(json.dumps({"images": {}}))
        assert not module.already_built(report, "ubuntu-24.04-target", images)

        # A corrupt report must not be read as permission to skip.
        report.write_text("{ not json")
        assert not module.already_built(report, "ubuntu-24.04-target", images)

    # And there must be a way to force a rebuild anyway.
    source = (root / "scripts/build-images.py").read_text()
    assert 'os.environ.get("REBUILD_IMAGES")' in source
