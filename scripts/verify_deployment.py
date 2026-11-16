#!/usr/bin/env python3
"""Read-only deployment-host checks for the xentry VM boundary.

Run this on the deployment host after installing the units, the QEMU user, and
the AppArmor profile. It does not change host state and never reads `.env`.
The WSL2 development host is expected to fail the AppArmor, nftables, and
systemd checks; those are deployment-host gates.

QEMU confinement comes from libvirt's AppArmor security driver: virt-aa-helper
generates a `libvirt-<uuid>` profile per domain from that domain's XML. There is
no static emulator profile to check for; run this during a job to assert the
running QEMU is enforcing under a generated profile.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = (
    Path("/var/lib/xentry/jobs"),
    Path("/var/lib/xentry/mirror"),
)
LIBVIRT_URI = "qemu:///system"
LIBVIRT_SECMODEL = "apparmor"
DOMAIN_PROFILE_PREFIX = "libvirt-"
HELPER_PROFILES = ("libvirtd", "virt-aa-helper")
APPARMOR_DROPIN = Path("/etc/apparmor.d/local/abstractions/libvirt-qemu")


def _run(command: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    return result.returncode, (result.stdout + result.stderr).strip()


def _run_split(command: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Like _run, but keeps stdout and stderr apart so output can be parsed."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return result.returncode, result.stdout, result.stderr.strip()


def _check(name: str, ok: bool, detail: str, *, required: bool = True) -> dict[str, Any]:
    return {"name": name, "ok": ok, "required": required, "detail": detail}


def _user(name: str) -> dict[str, Any]:
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        return _check(f"user:{name}", False, "user does not exist")
    return _check(f"user:{name}", True, f"uid={entry.pw_uid} home={entry.pw_dir}")


def _owner_checks() -> list[dict[str, Any]]:
    checks = []
    for path in REQUIRED_PATHS:
        try:
            stat = path.stat()
            owner = pwd.getpwuid(stat.st_uid).pw_name
        except FileNotFoundError:
            checks.append(_check(f"path:{path}", False, "missing"))
            continue
        except (OSError, KeyError) as exc:
            checks.append(_check(f"path:{path}", False, str(exc)))
            continue
        checks.append(
            _check(
                f"path:{path}",
                owner == "xentry",
                f"owner={owner} mode={stat.st_mode & 0o777:o}",
            )
        )
    return checks


def _file_check(name: str, path: Path) -> dict[str, Any]:
    try:
        return _check(name, path.is_file(), str(path))
    except OSError as exc:
        return _check(name, False, f"{path}: {exc}")


def _apparmor_status() -> tuple[dict[str, Any] | None, str]:
    """Return aa-status's parsed JSON, or None plus why it is unusable.

    `aa-status --profiled` is a legacy alias for `--count --profiles`: it
    prints the number of loaded profiles and never their names, so it cannot
    be matched against a profile name. Ask for the profile set instead.
    """
    code, detail = _run(["aa-status", "--json"])
    if code != 0:
        return None, (detail[:200] or f"aa-status exit {code}")
    try:
        data = json.loads(detail)
    except ValueError as exc:
        return None, f"aa-status --json unparsable: {exc}"
    if not isinstance(data, dict) or not isinstance(data.get("profiles"), dict):
        return None, "aa-status --json reported no profile set"
    return data, ""


def _libvirt_secmodel_check() -> dict[str, Any]:
    """Confirm libvirtd loaded the AppArmor security driver.

    This is the check that matters for the VM boundary. With
    `security_driver = "apparmor"` in /etc/libvirt/qemu.conf, libvirtd runs
    virt-aa-helper and switches each domain's QEMU into a generated
    `libvirt-<uuid>` profile built from that domain's own XML, so the
    allowed disk/seed/serial paths are exactly this job's. A hand-written
    profile attached to the emulator path is never entered in that
    configuration, which is why there is no static profile to check for.
    """
    name = f"libvirt secmodel:{LIBVIRT_SECMODEL}"
    code, out, err = _run_split(["virsh", "-r", "-c", LIBVIRT_URI, "capabilities"])
    if code != 0:
        return _check(name, False, (err or out)[:200] or f"virsh exit {code}")
    try:
        root = ET.fromstring(out)
    except ET.ParseError as exc:
        return _check(name, False, f"unparsable capabilities: {exc}")
    models = [
        (element.text or "").strip() for element in root.findall("./host/secmodel/model")
    ]
    if not models:
        return _check(name, False, "libvirtd reports no security model")
    return _check(name, LIBVIRT_SECMODEL in models, f"models={','.join(models)}")


def _qemu_confinement_check(data: dict[str, Any]) -> dict[str, Any]:
    """Confirm every running QEMU enforces under a generated domain profile.

    Nothing is confined while the host is idle, so this is advisory then and
    a required gate only once a job has a VM running. An unconfined or
    complain-mode QEMU is a failure.
    """
    name = "apparmor qemu confinement"
    idle = "no qemu process running (re-run during a job)"
    processes = data.get("processes")
    if not isinstance(processes, dict):
        return _check(name, False, idle, required=False)

    running: list[tuple[str, str, str]] = []
    for exe, entries in processes.items():
        if "qemu-system" not in exe or not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                running.append(
                    (
                        str(entry.get("pid", "?")),
                        str(entry.get("profile", "")),
                        str(entry.get("status", "")),
                    )
                )
    if not running:
        return _check(name, False, idle, required=False)

    bad = [
        f"pid={pid} profile={profile or 'unconfined'} mode={status or '?'}"
        for pid, profile, status in running
        if not profile.startswith(DOMAIN_PROFILE_PREFIX) or status != "enforce"
    ]
    if bad:
        return _check(name, False, "; ".join(bad)[:300])
    return _check(
        name,
        True,
        f"{len(running)} enforcing under {DOMAIN_PROFILE_PREFIX}*",
    )


def _apparmor_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    enabled_path = Path("/sys/module/apparmor/parameters/enabled")
    try:
        enabled = enabled_path.read_text().strip() == "Y"
        enabled_detail = str(enabled_path)
    except OSError as exc:
        enabled = False
        enabled_detail = f"{enabled_path}: {exc}"
    checks.append(_check("apparmor enabled", enabled, enabled_detail))

    checks.append(_libvirt_secmodel_check())
    checks.append(_file_check("apparmor xentry deny drop-in", APPARMOR_DROPIN))

    data, problem = _apparmor_status()
    if data is None:
        for profile in HELPER_PROFILES:
            checks.append(_check(f"apparmor profile:{profile}", False, problem))
        checks.append(_check("apparmor qemu confinement", False, problem, required=False))
        return checks

    profiles: dict[str, Any] = data["profiles"]
    for profile in HELPER_PROFILES:
        mode = profiles.get(profile)
        if mode is None:
            checks.append(_check(f"apparmor profile:{profile}", False, "profile not loaded"))
        else:
            checks.append(
                _check(f"apparmor profile:{profile}", mode == "enforce", f"mode={mode}")
            )

    checks.append(_qemu_confinement_check(data))
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, default=Path("/run/xentry/broker.sock"))
    parser.add_argument(
        "--artifacts-manifest",
        type=Path,
        default=ROOT / "var" / "artifacts" / "manifest.json",
    )
    parser.add_argument(
        "--images-manifest",
        type=Path,
        default=ROOT / "var" / "images" / "build-results.json",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    checks: list[dict[str, Any]] = []
    checks.append(
        _check(
            "python",
            sys.version_info[:2] == (3, 12),
            f"{sys.version_info.major}.{sys.version_info.minor}",
        )
    )
    kvm = Path("/dev/kvm")
    checks.append(
        _check(
            "kvm",
            kvm.exists() and os.access(kvm, os.R_OK | os.W_OK),
            f"{kvm} exists={kvm.exists()} rw={os.access(kvm, os.R_OK | os.W_OK)}",
        )
    )
    code, detail = _run(["virsh", "--version"])
    checks.append(_check("virsh", code == 0, detail))

    checks.append(_user("xentry"))
    checks.append(_user("xentry-vm"))

    try:
        stat = args.socket.stat()
    except FileNotFoundError:
        checks.append(_check("broker socket", False, f"missing {args.socket}"))
    except OSError as exc:
        checks.append(_check("broker socket", False, f"cannot stat {args.socket}: {exc}"))
    else:
        try:
            owner = pwd.getpwuid(stat.st_uid).pw_name
        except KeyError:
            owner = str(stat.st_uid)
        checks.append(
            _check(
                "broker socket",
                owner == "root" and (stat.st_mode & 0o777) == 0o660,
                f"owner={owner} mode={stat.st_mode & 0o777:o}",
            )
        )

    for unit in ("xentry-broker", "xentry"):
        code, detail = _run(["systemctl", "is-active", unit])
        checks.append(_check(f"unit:{unit}", code == 0 and detail == "active", detail))

    checks.extend(_apparmor_checks())

    code, detail = _run(["nft", "list", "table", "inet", "xentry"])
    checks.append(
        _check(
            "nftables phase table",
            code == 0,
            "table present" if code == 0 else "no active phase table (expected while idle)",
            required=False,
        )
    )

    checks.extend(_owner_checks())
    checks.append(_file_check("artifact manifest", args.artifacts_manifest))
    checks.append(_file_check("image build results", args.images_manifest))

    failed = [check for check in checks if check["required"] and not check["ok"]]
    summary = {"ok": not failed, "checks": checks, "failed": [item["name"] for item in failed]}
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        for check in checks:
            mark = "PASS" if check["ok"] else ("FAIL" if check["required"] else "INFO")
            print(f"{mark:4} {check['name']}: {check['detail']}")
        print(f"deployment checks: {'PASS' if not failed else 'FAIL'}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
