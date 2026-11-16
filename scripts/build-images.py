#!/usr/bin/env python3
"""Build the hash-pinned xentry Ubuntu image profiles.

The base cloud image is downloaded from the Gate G catalog and verified. Each
profile is a full qcow2 copy; cloud-init installs the manifest packages, writes
a success marker to the serial console, and powers the build VM off.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFESTS = ROOT / "config" / "image-manifests.yaml"
DEFAULT_CATALOG = ROOT / "config" / "artifacts.yaml"
DEFAULT_IMAGE_DIR = ROOT / "var" / "images"
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
SAFE_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
DISK_SIZE = "8G"
MARKER = "XENTRY_IMAGE_BUILD_OK"


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def validate(manifests: dict, catalog: dict) -> list[str]:
    errors: list[str] = []
    images = manifests.get("images") or {}
    artifacts = catalog.get("artifacts") or {}
    if not images:
        errors.append("image manifest has no images")
    for name, spec in images.items():
        if not SAFE_NAME.fullmatch(name):
            errors.append(f"{name}: unsafe image id")
        if not isinstance(spec, dict):
            errors.append(f"{name}: entry is not a mapping")
            continue
        base_id = spec.get("base_artifact")
        if not base_id:
            errors.append(f"{name}: missing base_artifact")
            continue
        base = artifacts.get(base_id)
        if not isinstance(base, dict):
            errors.append(f"{name}: unknown base artifact {base_id}")
            continue
        if base.get("kind") != "image":
            errors.append(f"{name}: base artifact {base_id} is not an image")
        if base.get("status") != "resolved":
            errors.append(f"{name}: base artifact {base_id} is unresolved")
        if str(base.get("url", "")).startswith("build://"):
            errors.append(f"{name}: base artifact {base_id} is itself a build artifact")
        if not re.fullmatch(r"[0-9a-f]{64}", str(base.get("sha256", ""))):
            errors.append(f"{name}: base artifact {base_id} has no SHA-256")
        packages = spec.get("packages")
        if not packages or not isinstance(packages, list):
            errors.append(f"{name}: missing packages")
            continue
        for kind in ("tarballs", "wheels"):
            for entry in spec.get(kind) or []:
                if not isinstance(entry, dict):
                    errors.append(f"{name}: a {kind} entry is not a mapping")
                    continue
                if not str(entry.get("url", "")).startswith("https://"):
                    errors.append(f"{name}: a {kind} entry has no https url")
                if len(str(entry.get("sha256", ""))) != 64:
                    errors.append(f"{name}: a {kind} entry has no sha256")
        for package in packages:
            if not isinstance(package, str) or not SAFE_PACKAGE.fullmatch(package):
                errors.append(f"{name}: unsafe package name {package!r}")
    return errors


def download(url: str, dest: Path, expected: str) -> None:
    if dest.exists() and sha256_file(dest) == expected:
        print(f"base image already verified: {dest}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    print(f"downloading {url}")
    with httpx.stream(
        "GET",
        url,
        follow_redirects=True,
        timeout=600.0,
        headers={"User-Agent": "xentry-image-build/0.1"},
    ) as response:
        response.raise_for_status()
        with part.open("wb") as handle:
            for chunk in response.iter_bytes():
                handle.write(chunk)
    actual = sha256_file(part)
    if actual != expected:
        part.unlink(missing_ok=True)
        raise SystemExit(f"base image hash mismatch: expected {expected}, got {actual}")
    part.replace(dest)
    print(f"verified base image: {dest}")


def tarball_commands(tarballs: list[dict]) -> str:
    """Unpack a digest-pinned tarball into the image.

    Some runtimes are not in the archive at a usable version: noble ships
    nodejs 18.19 and a current npm advisory needs 20 or later. nodejs.org
    publishes a sha256 per tarball in SHASUMS256.txt, so the runtime pins the
    way the Dirty Frag kernel does - the digest is checked here, in the build,
    and the built image is itself pinned by digest afterwards.
    """
    steps = []
    for entry in tarballs:
        url = str(entry["url"])
        digest = str(entry["sha256"])
        prefix = str(entry.get("prefix") or "/usr/local")
        archive = "/tmp/xentry-runtime" + Path(url).suffix
        steps.append(
            f"curl -fsSL --retry 3 -o {archive} {url}; "
            f"echo '{digest}  {archive}' | sha256sum -c -; "
            f"mkdir -p {prefix}; "
            f"tar -C {prefix} --strip-components=1 -xf {archive}; "
            f"rm -f {archive}; "
        )
    return "".join(steps)


def wheel_commands(wheels: list[dict[str, Any]]) -> str:
    """Install digest-pinned Python wheels into the image.

    A PoC's own dependencies are not a per-job resolution. The attacker VM has
    no network once the job locks it, so `build-poc-generic.sh` fails any PoC
    whose imports are not already there - and the set those PoCs reach for is
    small, shared and slow-moving. CVE-2026-56290's PoC needs requests and
    colorama; the image carried only the first.

    So the set is resolved once on the host, where `pip install --dry-run
    --report` gives a sha256 and an exact URL per file, and listed here. pip
    checks every digest itself under --require-hashes, so a wheel that does not
    match fails the build rather than reaching an attacker VM. --no-deps is
    safe because the list is a full closure, not a top-level ask.

    --break-system-packages is deliberate: this is a disposable VM built from a
    pinned image, there is nothing in it to break, and a venv would be invisible
    to a PoC that simply runs `python3 exploit.py`.
    """
    if not wheels:
        return ""
    lines = "".join(
        f"{entry['url']} --hash=sha256:{entry['sha256']}\n" for entry in wheels
    )
    return (
        "cat > /tmp/xentry-wheels.txt <<'XENTRYWHEELS'\n"
        f"{lines}"
        "XENTRYWHEELS\n"
        "pip3 install --no-cache-dir --no-deps --require-hashes "
        "--break-system-packages -r /tmp/xentry-wheels.txt; "
        "rm -f /tmp/xentry-wheels.txt; "
    )


def cloud_init(
    name: str,
    packages: list[str],
    work: Path,
    tarballs: list[dict] | None = None,
    wheels: list[dict[str, Any]] | None = None,
) -> Path:
    command = (
        "set -euo pipefail; export DEBIAN_FRONTEND=noninteractive; "
        "apt-get update; "
        # --no-upgrade, so a RELEASE-DAY base image stays on release-pocket
        # versions. This install runs against the image's OWN sources, which
        # are the live archive, so without it ca-certificates, curl and
        # ubuntu-keyring would be upgraded to -updates builds and drag their
        # dependencies with them - putting back exactly the mismatch the
        # release-day pin exists to remove. These three are already present in
        # an Ubuntu cloud image, so this is normally a no-op; where one is
        # genuinely absent it is still installed.
        "apt-get install -y --no-install-recommends --no-upgrade "
        + " ".join(packages)
        + "; "
        + tarball_commands(tarballs or [])
        + wheel_commands(wheels or [])
        + "apt-get clean; rm -rf /var/lib/apt/lists/*; "
        f"echo {MARKER}"
    )
    user_data = {
        "hostname": "xentry-image-build",
        "manage_etc_hosts": True,
        "ssh_pwauth": False,
        "package_update": False,
        "runcmd": [["bash", "-lc", command]],
        "power_state": {
            "mode": "poweroff",
            "timeout": 120,
            "message": "xentry image build complete",
        },
    }
    meta_data = {
        "instance-id": f"xentry-image-build-{name}",
        "local-hostname": "xentry-image-build",
    }
    user_path = work / f"{name}-user-data.yaml"
    meta_path = work / f"{name}-meta-data.yaml"
    user_path.write_text("#cloud-config\n" + yaml.safe_dump(user_data, sort_keys=False), encoding="utf-8")
    meta_path.write_text(yaml.safe_dump(meta_data, sort_keys=False), encoding="utf-8")
    seed = work / f"{name}-seed.iso"
    seed.unlink(missing_ok=True)
    subprocess.run(["cloud-localds", str(seed), str(user_path), str(meta_path)], check=True)
    return seed


def build_one(name: str, spec: dict, base: Path, out_dir: Path, work: Path) -> Path:
    image = work / f"{name}.qcow2"
    image.unlink(missing_ok=True)
    print(f"[{name}] copying base image")
    subprocess.run(
        ["qemu-img", "convert", "-O", "qcow2", str(base), str(image)],
        check=True,
    )
    # Grown before boot, because a cloud image is sized for its own contents
    # and not for ours. jammy's is 2.20GiB with 0.68GiB already used, and
    # apt-get update over four components of jammy, jammy-updates and
    # jammy-security filled it: the build died inside the guest with
    # "No space left on device", cloud-init powered the VM off cleanly, and
    # the only sign was a missing completion marker. focal fit with about
    # 100MiB to spare, which is luck rather than a margin. cloud-init's
    # growpart extends the root partition on first boot, so one size for every
    # release makes a build depend on the manifest instead of on how tightly
    # that release's publisher happened to pack its image. qcow2 stays sparse,
    # so this costs nothing on disk.
    subprocess.run(["qemu-img", "resize", str(image), DISK_SIZE], check=True)
    seed = cloud_init(
        name,
        list(spec["packages"]),
        work,
        list(spec.get("tarballs") or []),
        list(spec.get("wheels") or []),
    )
    log = work / f"{name}-console.log"
    log.unlink(missing_ok=True)
    command = [
        "qemu-system-x86_64",
        "-machine",
        "accel=kvm",
        "-cpu",
        "host",
        "-m",
        "2048",
        "-smp",
        "2",
        "-drive",
        f"file={image},if=virtio,format=qcow2",
        "-drive",
        f"file={seed},if=virtio,format=raw,readonly=on",
        "-netdev",
        "user,id=net0",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-display",
        "none",
        "-serial",
        f"file:{log}",
        "-monitor",
        "none",
        "-no-reboot",
    ]
    print(f"[{name}] booting build VM")
    with log.open("wb") as handle:
        result = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, check=False)
    text = log.read_text(encoding="utf-8", errors="replace")
    if MARKER not in text:
        tail = "\n".join(text.splitlines()[-40:])
        raise SystemExit(f"[{name}] build failed (qemu exit {result.returncode})\n{tail}")
    final = out_dir / f"{name}.qcow2"
    final.unlink(missing_ok=True)
    shutil.move(str(image), final)
    print(f"[{name}] built {final} ({final.stat().st_size} bytes)")
    return final


def record(report_path: Path, name: str, result: dict[str, object]) -> None:
    """Merge one image's result into the build report, keeping the others."""
    images: dict[str, dict[str, object]] = {}
    if report_path.exists():
        try:
            images = json.loads(report_path.read_text(encoding="utf-8")).get("images", {})
        except (json.JSONDecodeError, AttributeError):
            images = {}
    images[name] = result
    report = {"generated_at": now_iso(), "images": images}
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifests", type=Path, default=DEFAULT_MANIFESTS)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--image-dir", type=Path, default=DEFAULT_IMAGE_DIR)
    parser.add_argument("--mode", choices=("dry-run", "execute"), default="dry-run")
    parser.add_argument("--only", action="append", default=[])
    args = parser.parse_args()

    manifests = load_yaml(args.manifests)
    catalog = load_yaml(args.catalog)
    errors = validate(manifests, catalog)
    if errors:
        print("Image manifest: BLOCKED")
        for error in errors:
            print(f" - {error}")
        return 1
    images = manifests["images"]
    selected = args.only or list(images)
    unknown = [name for name in selected if name not in images]
    if unknown:
        print(f"Image manifest: unknown image(s): {', '.join(unknown)}")
        return 1
    print(f"Image manifest: PASS ({len(images)} images)")
    if args.mode == "dry-run":
        print("Dry run only; no images were built.")
        return 0

    for tool in ("qemu-img", "qemu-system-x86_64", "cloud-localds"):
        if shutil.which(tool) is None:
            print(f"missing required tool: {tool}", file=sys.stderr)
            return 1
    if not Path("/dev/kvm").exists():
        print("missing /dev/kvm; image builds require KVM", file=sys.stderr)
        return 1

    work = args.image_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    artifacts = catalog["artifacts"]
    report_path = args.image_dir / "build-results.json"
    for name in selected:
        spec = images[name]
        base_spec = artifacts[spec["base_artifact"]]
        # Keyed by artifact: three releases have three different base images,
        # and one shared filename would make each build overwrite the last.
        base_path = args.image_dir / f"{spec['base_artifact']}.img"
        download(base_spec["url"], base_path, base_spec["sha256"])
        final = build_one(name, spec, base_path, args.image_dir, work)
        # Recorded per image rather than after the loop: build_one raises on a
        # failed build, and a report written at the end would have discarded
        # the digest of every image already built.
        record(
            report_path,
            name,
            {
                "path": str(final),
                "sha256": sha256_file(final),
                "bytes": final.stat().st_size,
            },
        )
        print(f"[{name}] recorded in {report_path}")
    print("Pin each image with scripts/pin-artifact.py --accept after reviewing the hash.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
