#!/usr/bin/env python3
"""Run the PHP2Shell target setup/readiness through the broker."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import subprocess
import time
from pathlib import Path

import yaml

from broker.main import BrokerServer
from broker.runtime import BrokerRuntime
from xentry.broker import BrokerClient

ROOT = Path(__file__).resolve().parents[1]


def wait_ssh(key: Path, user: str, ip: str, timeout_s: int = 180) -> None:
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        result = subprocess.run(
            [
                "ssh",
                "-i",
                str(key),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                f"{user}@{ip}",
                "true",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode == 0:
            return
        last = result.stderr
        time.sleep(3)
    raise RuntimeError(f"SSH did not become ready: {last}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=ROOT / "var" / "smoke" / "php")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    parser.add_argument("--qemu-user", default=os.environ.get("XENTRY_QEMU_USER", ""))
    args = parser.parse_args()

    data_dir = args.data_dir
    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True)
    qemu_user = args.qemu_user
    if not qemu_user and os.getuid() != 0:
        qemu_user = pwd.getpwuid(os.getuid()).pw_name

    catalog = yaml.safe_load((ROOT / "config" / "artifacts.yaml").read_text(encoding="utf-8"))
    artifacts = catalog["artifacts"]
    runtime = BrokerRuntime(
        data_dir,
        ROOT / "var" / "images",
        catalog_path=ROOT / "config" / "artifacts.yaml",
        apply_nft=False,
        qemu_user=qemu_user or None,
        manifest_path=ROOT / "var" / "artifacts" / "manifest.json",
        start_mirror=True,
        steps_manifest=ROOT / "targets" / "steps.yaml",
        targets_dir=ROOT / "targets",
    )
    server = BrokerServer(
        data_dir / "broker.sock",
        data_dir / "jobs",
        allowed_uids={os.getuid()},
        runtime=runtime,
    )
    server.start()
    client = BrokerClient(data_dir / "broker.sock", timeout=2400)
    job_id = "php-smoke"
    target_vm = None
    try:
        net = client.call("create_network", {"job_id": job_id, "profile_id": "isolated"})
        print("network", json.dumps(net, sort_keys=True), flush=True)
        target = client.call(
            "create_target",
            {"job_id": job_id, "target_id": "php2shell", "image_id": "ubuntu-24.04-target"},
        )
        target_vm = target["vm_id"]
        print("target", json.dumps(target, sort_keys=True), flush=True)
        wait_ssh(data_dir / "jobs" / job_id / "keys" / "root", "root", target["guest_ip"])
        setup = client.call(
            "exec",
            {
                "vm_id": target_vm,
                "step_id": "setup-php",
                "params": {
                    "proxy_url": net["proxy_url"],
                    "php_artifact_id": "php-8.4.26-src",
                    "php_sha256": artifacts["php-8.4.26-src"]["sha256"],
                },
                "tty": False,
                "timeout_s": 1800,
            },
        )
        print(
            f"setup exit={setup['exit_code']} duration_ms={setup['duration_ms']}",
            flush=True,
        )
        print("setup stdout tail:", setup["stdout"][-4000:], flush=True)
        print("setup stderr tail:", setup["stderr"][-2000:], flush=True)
        if setup["exit_code"] != 0:
            return 1
        ready = client.call(
            "exec",
            {
                "vm_id": target_vm,
                "step_id": "readiness-php",
                "params": {},
                "tty": False,
                "timeout_s": 300,
            },
        )
        print("readiness", json.dumps(ready, sort_keys=True), flush=True)
        return 0 if ready["exit_code"] == 0 else 1
    finally:
        if target_vm and not args.keep_running:
            try:
                print("destroy target", client.call("destroy_vm", {"vm_id": target_vm}), flush=True)
            except Exception as exc:  # noqa: BLE001
                print("destroy target failed", exc, flush=True)
        if not args.keep_running:
            try:
                print(
                    "destroy network",
                    client.call("destroy_network", {"network_id": f"xentry-{job_id}"}),
                    flush=True,
                )
            except Exception as exc:  # noqa: BLE001
                print("destroy network failed", exc, flush=True)
        server.stop()
        if not args.keep:
            shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
