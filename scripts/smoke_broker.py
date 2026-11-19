#!/usr/bin/env python3
"""Phase 0 two-VM broker smoke. This is not a target acceptance run."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pwd
import secrets
import shutil
import subprocess
import time
from pathlib import Path

from broker.main import BrokerServer
from broker.runtime import BrokerRuntime
from xentry.broker import BrokerClient, BrokerError

ROOT = Path(__file__).resolve().parents[1]


def ssh(key: Path, user: str, ip: str, command: str, timeout: int = 30) -> tuple[int, str, str]:
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
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def wait_ssh(key: Path, user: str, ip: str, timeout_s: int = 180) -> tuple[int, str, str]:
    deadline = time.monotonic() + timeout_s
    last: tuple[int, str, str] = (1, "", "not attempted")
    while time.monotonic() < deadline:
        last = ssh(key, user, ip, "id -u", timeout=20)
        if last[0] == 0:
            return last
        time.sleep(3)
    return last


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=ROOT / "var" / "smoke" / "broker")
    parser.add_argument("--keep", action="store_true", help="keep the smoke data directory")
    parser.add_argument("--qemu-user", default=os.environ.get("XENTRY_QEMU_USER", ""))
    parser.add_argument("--start-mirror", action="store_true")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "var" / "artifacts" / "manifest.json",
    )
    args = parser.parse_args()

    data_dir = args.data_dir
    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True)

    qemu_user = args.qemu_user
    if not qemu_user and os.getuid() != 0:
        qemu_user = pwd.getpwuid(os.getuid()).pw_name

    runtime = BrokerRuntime(
        data_dir,
        ROOT / "var" / "images",
        catalog_path=ROOT / "config" / "artifacts.yaml",
        apply_nft=False,
        qemu_user=qemu_user or None,
        manifest_path=args.manifest,
        start_mirror=args.start_mirror,
    )
    server = BrokerServer(
        data_dir / "broker.sock",
        data_dir / "jobs",
        allowed_uids={os.getuid()},
        runtime=runtime,
    )
    server.start()
    client = BrokerClient(data_dir / "broker.sock", timeout=300)
    job_id = "smoke-1"
    target_vm: str | None = None
    attacker_vm: str | None = None
    try:
        net = client.call("create_network", {"job_id": job_id, "profile_id": "isolated"})
        print("network", json.dumps(net, sort_keys=True))
        target = client.call(
            "create_target",
            {"job_id": job_id, "target_id": "php2shell", "image_id": "ubuntu-24.04-target"},
        )
        target_vm = target["vm_id"]
        print("target", json.dumps(target, sort_keys=True))
        keys = data_dir / "jobs" / job_id / "keys"
        root_key = keys / "root"
        actor_key = keys / "actor"
        rc, out, err = wait_ssh(root_key, "root", target["guest_ip"])
        print(f"target root ssh rc={rc} out={out!r} err={err!r}")
        rc, out, err = wait_ssh(actor_key, "xentry-guest", target["guest_ip"])
        print(f"target actor ssh rc={rc} out={out!r} err={err!r}")
        exec_result = client.call(
            "exec",
            {
                "vm_id": target_vm,
                "step_id": "null-dirtyfrag",
                "params": {},
                "tty": False,
                "timeout_s": 60,
            },
        )
        print(
            f"broker exec step=null-dirtyfrag exit={exec_result['exit_code']} "
            f"out={exec_result['stdout']!r}"
        )
        if net.get("mirror_started"):
            url = f"{net['proxy_url']}/artifacts/php-8.4.26-src"
            rc, out, err = ssh(
                root_key,
                "root",
                target["guest_ip"],
                f"curl -fsS {url} -o /tmp/php.tar.xz && sha256sum /tmp/php.tar.xz",
            )
            print(f"target mirror fetch rc={rc} out={out!r} err={err!r}")
        copied = client.call(
            "copy_in",
            {
                "vm_id": target_vm,
                "artifact_id": "poc-php2shell",
                "guest_path": "poc.tar.gz",
            },
        )
        print(f"copy_in sha256={copied['sha256']} remote={copied['remote_path']}")
        rc, out, err = ssh(
            actor_key,
            "xentry-guest",
            target["guest_ip"],
            "sha256sum /var/lib/xentry/artifacts/poc.tar.gz",
        )
        print(f"actor copied artifact rc={rc} out={out!r} err={err!r}")
        rc, out, err = ssh(
            root_key,
            "root",
            target["guest_ip"],
            "printf 'xentry-host-evidence-test\\n' > /dev/ttyS0",
        )
        print(f"serial write rc={rc} err={err!r}")
        try:
            evidence: dict[str, object] = {}
            for _ in range(10):
                evidence = client.call(
                    "read_host_evidence",
                    {"vm_id": target_vm, "channel": "org.xentry.evidence.0"},
                )
                if evidence.get("size"):
                    break
                time.sleep(1)
            payload = base64.b64decode(str(evidence.get("bytes_b64", "")))
            print(
                f"host evidence size={evidence.get('size')} sha256={evidence.get('sha256')} "
                f"marker={b'xentry-host-evidence-test' in payload}"
            )
        except BrokerError as exc:
            print(f"host evidence unavailable in dev broker: {exc}")
        nonce = secrets.token_hex(16)
        placed = client.call(
            "place_nonce",
            {
                "vm_id": target_vm,
                "nonce_id": "nonce-smoke",
                "path": "/root/xentry-nonce",
                "owner": "root",
                "mode": 0o600,
                "value": nonce,
            },
        )
        assert placed["sha256"] == hashlib.sha256(nonce.encode()).hexdigest()
        print(f"nonce placed sha256={placed['sha256']}")
        rc, out, err = ssh(
            root_key,
            "root",
            target["guest_ip"],
            "stat -c '%a %U %s' /root/xentry-nonce",
        )
        print(f"nonce stat rc={rc} out={out!r} err={err!r}")
        rc, out, err = ssh(
            actor_key,
            "xentry-guest",
            target["guest_ip"],
            "cat /root/xentry-nonce >/dev/null",
        )
        print(f"actor nonce read rc={rc} err={err!r}")
        attacker = client.call(
            "create_attacker",
            {"job_id": job_id, "profile_id": "attacker-remote", "image_id": "ubuntu-24.04-attacker"},
        )
        attacker_vm = attacker["vm_id"]
        print("attacker", json.dumps(attacker, sort_keys=True))
        rc, out, err = wait_ssh(root_key, "root", attacker["guest_ip"])
        print(f"attacker root ssh rc={rc} out={out!r} err={err!r}")
        rc, out, err = ssh(
            root_key,
            "root",
            attacker["guest_ip"],
            f"timeout 5 bash -c 'echo > /dev/tcp/{target['guest_ip']}/22' && echo reachable || echo blocked",
        )
        print(f"attacker->target rc={rc} out={out!r} err={err!r}")
        print("managed", json.dumps(client.call("list_managed"), sort_keys=True))
    finally:
        for vm in (attacker_vm, target_vm):
            if vm:
                try:
                    print("destroy", vm, json.dumps(client.call("destroy_vm", {"vm_id": vm})))
                except Exception as exc:  # noqa: BLE001 - cleanup must continue
                    print("destroy failed", vm, exc)
        try:
            print(
                "destroy network",
                json.dumps(
                    client.call("destroy_network", {"network_id": f"xentry-{job_id}"})
                ),
            )
        except Exception as exc:  # noqa: BLE001 - cleanup must continue
            print("destroy network failed", exc)
        server.stop()
        if not args.keep:
            shutil.rmtree(data_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
