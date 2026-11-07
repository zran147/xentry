#!/usr/bin/env python3
"""Read-only deployment-host checks for the xentry VM boundary.

Run this on the deployment host after installing the units, the QEMU user, and
the AppArmor profile. It does not change host state and never reads `.env`.
The WSL2 development host is expected to fail the AppArmor, nftables, and
systemd checks; those are deployment-host gates.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = (
    Path("/var/lib/xentry/jobs"),
    Path("/var/lib/xentry/mirror"),
)
APPARMOR_PROFILE = "xentry-vm"


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
        if not path.exists():
            checks.append(_check(f"path:{path}", False, "missing"))
            continue
        try:
            stat = path.stat()
            owner = pwd.getpwuid(stat.st_uid).pw_name
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

    if args.socket.exists():
        stat = args.socket.stat()
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
    else:
        checks.append(_check("broker socket", False, f"missing {args.socket}"))

    for unit in ("xentry-broker", "xentry"):
        code, detail = _run(["systemctl", "is-active", unit])
        checks.append(_check(f"unit:{unit}", code == 0 and detail == "active", detail))

    apparmor_enabled = Path("/sys/module/apparmor/parameters/enabled")
    enabled = apparmor_enabled.exists() and apparmor_enabled.read_text().strip() == "Y"
    checks.append(_check("apparmor enabled", enabled, str(apparmor_enabled)))
    code, detail = _run(["aa-status", "--profiled"])
    profiled = code == 0 and APPARMOR_PROFILE in detail
    checks.append(
        _check(
            f"apparmor profile:{APPARMOR_PROFILE}",
            profiled,
            "profile loaded" if profiled else detail[:300],
        )
    )

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
    checks.append(
        _check(
            "artifact manifest",
            args.artifacts_manifest.is_file(),
            str(args.artifacts_manifest),
        )
    )
    checks.append(
        _check(
            "image build results",
            args.images_manifest.is_file(),
            str(args.images_manifest),
        )
    )

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
