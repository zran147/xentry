"""Broker runtime: network, VM lifecycle, and per-job state.

The runtime is the only place that turns broker ids into libvirt XML, image
paths, cloud-init seeds, and SSH keys. It is called by the socket dispatch layer.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import posixpath
import pwd
import re
import shlex
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import asyncssh
import yaml

from broker.errors import BrokerError
from broker.exec_ops import SSHError, SSHTransport
from broker.libvirt_ops import LibvirtError, Virsh, domain_xml, network_xml
from broker.mirror import ArtifactMirror, MirrorError
from broker.network_ops import Nftables, NftablesError, provisioning_rules
from broker.proxy import CaptureError, ProxyCapture, SerialCapture, parse_capture
from broker.registry import (
    RegistryError,
    resolve_image,
    resolve_profile,
    resolve_step,
    resolve_target,
)
from broker.steps import StepRegistry

JOB_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VM_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32,128}$")
OWNER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
TARGET_MAC = "52:54:00:00:00:10"
ATTACKER_MAC = "52:54:00:00:00:20"
TARGET_IP = "10.42.0.10"
ATTACKER_IP = "10.42.0.20"
BRIDGE = "xentry0"
MIRROR_URL = "http://10.42.0.1:8081"
ATTACKER_PROFILE_ID = "attacker-remote"
ATTACKER_IMAGE_ID = "ubuntu-24.04-attacker"


@dataclass(frozen=True)
class Resources:
    vcpu: int
    memory_mb: int
    disk_gb: int
    target_ports: tuple[int, ...] = ()


TARGET_PROFILES = {
    "php2shell": Resources(vcpu=2, memory_mb=4096, disk_gb=25, target_ports=(8088,)),
    "gitlab": Resources(vcpu=4, memory_mb=8192, disk_gb=50, target_ports=(80, 443)),
    "dirtyfrag": Resources(vcpu=2, memory_mb=2048, disk_gb=25),
}
TARGET_IMAGES = {
    "php2shell": "ubuntu-24.04-target",
    "gitlab": "ubuntu-24.04-target",
    "dirtyfrag": "ubuntu-24.04-dirtyfrag",
}
ATTACKER_RESOURCES = Resources(vcpu=2, memory_mb=2048, disk_gb=10)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(params: dict[str, Any], key: str, max_len: int = 128) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise BrokerError("broker_registry_rejected", f"invalid {key}")
    return value


def _integer(params: dict[str, Any], key: str, minimum: int, maximum: int) -> int:
    value = params.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise BrokerError("broker_registry_rejected", f"invalid {key}")
    if not minimum <= value <= maximum:
        raise BrokerError("broker_registry_rejected", f"{key} out of range")
    return value


def _guest_path(params: dict[str, Any], key: str = "guest_path") -> str:
    value = _text(params, key, max_len=400)
    if value.startswith("/") or ".." in Path(value).parts or "\\" in value:
        raise BrokerError("broker_registry_rejected", f"invalid {key}")
    return value


class BrokerRuntime:
    def __init__(
        self,
        data_dir: Path,
        image_dir: Path,
        *,
        catalog_path: Path | None = None,
        apply_nft: bool = True,
        qemu_user: str | None = None,
        virsh: Virsh | None = None,
        nft: Nftables | None = None,
        manifest_path: Path | None = None,
        start_mirror: bool = False,
        mirror_bind: str = "10.42.0.1",
        mirror_port: int = 8081,
        steps_manifest: Path | None = None,
        targets_dir: Path | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.image_dir = Path(image_dir)
        self.jobs_root = self.data_dir / "jobs"
        self.catalog_path = Path(
            catalog_path
            or os.environ.get("XENTRY_ARTIFACT_CATALOG", "config/artifacts.yaml")
        )
        self.apply_nft = apply_nft
        self.qemu_user = self._qemu_label(qemu_user)
        self.virsh = virsh or Virsh(timeout_s=300)
        self.nft = nft or Nftables()
        self.manifest_path = Path(manifest_path) if manifest_path else None
        self.start_mirror = start_mirror
        self.mirror_bind = mirror_bind
        self.mirror_port = mirror_port
        self.mirror: ArtifactMirror | None = None
        self.steps_manifest = Path(
            steps_manifest or os.environ.get("XENTRY_STEPS_MANIFEST", "targets/steps.yaml")
        )
        self.targets_dir = Path(targets_dir or os.environ.get("XENTRY_TARGETS_DIR", "targets"))
        self._step_registry: StepRegistry | None = None
        self._catalog: dict[str, dict[str, Any]] | None = None
        self._build_results: dict[str, Any] | None = None
        self._image_cache: dict[str, str] = {}
        self._serial_captures: dict[str, SerialCapture] = {}

    @staticmethod
    def _qemu_label(name: str | None) -> str | None:
        if not name:
            return None
        try:
            entry = pwd.getpwnam(name)
            return f"{entry.pw_uid}:{entry.pw_gid}"
        except KeyError as exc:
            if ":" in name and all(part.isdigit() for part in name.split(":", 1)):
                return name
            raise BrokerError("preflight_refused", f"unknown QEMU user: {name}") from exc

    @staticmethod
    def _free_tcp_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _catalog_data(self) -> dict[str, dict[str, Any]]:
        if self._catalog is None:
            if not self.catalog_path.exists():
                raise BrokerError("preflight_refused", f"missing artifact catalog: {self.catalog_path}")
            data = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8")) or {}
            artifacts = data.get("artifacts")
            if not isinstance(artifacts, dict):
                raise BrokerError("preflight_refused", "artifact catalog has no artifacts")
            self._catalog = artifacts
        return self._catalog

    def _results_data(self) -> dict[str, Any]:
        if self._build_results is None:
            path = self.image_dir / "build-results.json"
            if not path.exists():
                raise BrokerError("preflight_refused", f"missing image build results: {path}")
            self._build_results = json.loads(path.read_text(encoding="utf-8"))
        return self._build_results

    def _image_path(self, image_id: str) -> Path:
        try:
            artifact_id = resolve_image(image_id)
        except RegistryError as exc:
            raise BrokerError("broker_registry_rejected", str(exc)) from exc
        if image_id in self._image_cache:
            return Path(self._image_cache[image_id])
        entry = (self._results_data().get("images") or {}).get(image_id)
        if not isinstance(entry, dict) or not entry.get("path"):
            raise BrokerError("preflight_refused", f"image is not built: {image_id}")
        path = Path(str(entry["path"]))
        if not path.is_absolute():
            path = self.image_dir / path
        artifact = self._catalog_data().get(artifact_id)
        if not isinstance(artifact, dict) or artifact.get("status") != "resolved":
            raise BrokerError("preflight_refused", f"image artifact is unresolved: {artifact_id}")
        if not path.exists():
            raise BrokerError("preflight_refused", f"image file is missing: {path}")
        actual = _sha256_file(path)
        if actual != artifact["sha256"]:
            raise BrokerError("artifact_hash_mismatch", f"image hash mismatch: {image_id}")
        self._image_cache[image_id] = str(path)
        return path

    def _job_dir(self, job_id: str) -> Path:
        if not JOB_ID_RE.fullmatch(job_id):
            raise BrokerError("broker_registry_rejected", "invalid job_id")
        path = self.jobs_root / job_id
        path.mkdir(parents=True, exist_ok=True, mode=0o750)
        return path

    def _ensure_keys(self, job_id: str) -> tuple[str, str]:
        key_dir = self._job_dir(job_id) / "keys"
        key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        root_private = key_dir / "root"
        root_public = key_dir / "root.pub"
        actor_private = key_dir / "actor"
        actor_public = key_dir / "actor.pub"
        for private_path, public_path in (
            (root_private, root_public),
            (actor_private, actor_public),
        ):
            if private_path.exists() and public_path.exists():
                continue
            key = asyncssh.generate_private_key("ssh-ed25519")
            private_path.write_bytes(key.export_private_key())
            public_path.write_bytes(key.export_public_key())
            private_path.chmod(0o600)
            public_path.chmod(0o644)
        return (
            root_public.read_text(encoding="utf-8").strip(),
            actor_public.read_text(encoding="utf-8").strip(),
        )

    def _seed(
        self,
        job_id: str,
        role: str,
        root_key: str,
        actor_key: str,
        failure_code: str,
    ) -> Path:
        seed_dir = self._job_dir(job_id) / role
        seed_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        user_data = {
            "hostname": f"xentry-{role}",
            "manage_etc_hosts": True,
            "disable_root": False,
            "ssh_pwauth": False,
            "package_update": False,
            "users": [
                {"name": "root", "lock_passwd": False, "ssh_authorized_keys": [root_key]},
                {
                    "name": "xentry-guest",
                    "shell": "/bin/bash",
                    "sudo": False,
                    "ssh_authorized_keys": [actor_key],
                },
            ],
            "runcmd": [
                [
                    "bash",
                    "-lc",
                    "install -d -m 0755 /var/lib/xentry; echo ready > /var/lib/xentry/ready",
                ]
            ],
        }
        meta_data = {
            "instance-id": f"xentry-{job_id}-{role}-{uuid.uuid4().hex}",
            "local-hostname": f"xentry-{role}",
        }
        user_path = seed_dir / "user-data.yaml"
        meta_path = seed_dir / "meta-data.yaml"
        user_path.write_text(
            "#cloud-config\n" + yaml.safe_dump(user_data, sort_keys=False),
            encoding="utf-8",
        )
        meta_path.write_text(yaml.safe_dump(meta_data, sort_keys=False), encoding="utf-8")
        seed_path = seed_dir / "seed.iso"
        seed_path.unlink(missing_ok=True)
        try:
            subprocess.run(
                ["cloud-localds", str(seed_path), str(user_path), str(meta_path)],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise BrokerError(failure_code, f"cloud-init seed failed: {exc}") from exc
        return seed_path

    def _wait_for_ip(
        self,
        network: str,
        mac: str,
        failure_code: str,
        timeout_s: int = 180,
    ) -> str:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            ip = self.virsh.network_lease_ip(network, mac)
            if ip:
                return ip
            time.sleep(2)
        raise BrokerError(failure_code, f"no DHCP lease for {mac} on {network}")

    def _create_vm(
        self,
        *,
        job_id: str,
        role: str,
        image_id: str,
        resources: Resources,
        mac: str,
        failure_code: str,
    ) -> dict[str, Any]:
        job_dir = self._job_dir(job_id)
        network_name = f"xentry-{job_id}"
        if not self.virsh.network_exists(network_name) or not self.virsh.network_active(network_name):
            raise BrokerError("preflight_refused", f"network is not active: {network_name}")
        image = self._image_path(image_id)
        vm_dir = job_dir / role
        vm_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        # The broker's umask keeps job directories private, but QEMU runs as
        # xentry-vm and must traverse them to reach its own overlay/seed. Give
        # execute-only access on the ancestors; the VM directory itself is
        # chowned to the QEMU user below.
        for parent in (self.data_dir, self.jobs_root, job_dir, vm_dir):
            parent.chmod(parent.stat().st_mode | 0o001)
        overlay = vm_dir / f"{role}.qcow2"
        overlay.unlink(missing_ok=True)
        try:
            subprocess.run(
                [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    "-b",
                    str(image),
                    "-F",
                    "qcow2",
                    str(overlay),
                    f"{resources.disk_gb}G",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise BrokerError(failure_code, f"overlay failed: {exc}") from exc
        root_key, actor_key = self._ensure_keys(job_id)
        seed = self._seed(job_id, role, root_key, actor_key, failure_code)
        serial = vm_dir / f"{role}-serial.log"
        serial.touch(mode=0o640, exist_ok=True)
        serial_log = vm_dir / f"{role}-serial-qemu.log"
        serial_tcp_port = self._free_tcp_port() if role == "target" else None
        if self.qemu_user:
            try:
                uid, gid = (int(part) for part in self.qemu_user.split(":", 1))
                for path in (vm_dir, overlay, seed, serial):
                    os.chown(path, uid, gid)
            except (ValueError, OSError) as exc:
                raise BrokerError(failure_code, f"cannot set QEMU ownership: {exc}") from exc
        domain_name = f"xentry-{job_id}-{role}"
        xml = domain_xml(
            name=domain_name,
            memory_mb=resources.memory_mb,
            vcpu=resources.vcpu,
            disk_path=overlay.resolve(),
            seed_path=seed.resolve(),
            network_name=network_name,
            mac=mac,
            qemu_user=self.qemu_user,
            serial_path=serial.resolve(),
            serial_log_path=serial_log.resolve(),
            serial_tcp_port=serial_tcp_port,
            vhost=role != "target",
        )
        xml_path = vm_dir / f"{role}.xml"
        xml_path.write_text(xml, encoding="utf-8")
        try:
            if self.virsh.domain_exists(domain_name):
                try:
                    self.virsh.domain_destroy(domain_name)
                except LibvirtError:
                    pass
                self.virsh.domain_undefine(domain_name)
            self.virsh.domain_define(xml_path)
            self.virsh.domain_start(domain_name)
            guest_ip = self._wait_for_ip(network_name, mac, failure_code)
            if serial_tcp_port is not None:
                serial_capture = SerialCapture(
                    "127.0.0.1",
                    serial_tcp_port,
                    serial_log,
                )
                serial_capture.start()
                self._serial_captures[domain_name] = serial_capture
        except (LibvirtError, BrokerError) as exc:
            self._cleanup_vm_files(domain_name, overlay, seed, xml_path)
            if isinstance(exc, BrokerError):
                raise
            raise BrokerError(failure_code, str(exc)) from exc
        state = {
            "vm_id": domain_name,
            "job_id": job_id,
            "role": role,
            "guest_ip": guest_ip,
            "mac": mac,
            "overlay": str(overlay),
            "seed": str(seed),
            "xml": str(xml_path),
            "serial": str(serial),
            "serial_log": str(serial_log),
            "serial_tcp_port": serial_tcp_port,
            "created_at": _now(),
        }
        (vm_dir / "state.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {
            "vm_id": domain_name,
            "guest_ip": guest_ip,
            "domain": domain_name,
            "role": role,
            "job_id": job_id,
        }

    def _cleanup_network(self, network_name: str) -> None:
        if self.apply_nft:
            try:
                self.nft.clear()
            except NftablesError:
                pass
        try:
            if self.virsh.network_active(network_name):
                self.virsh.network_destroy(network_name)
            if self.virsh.network_exists(network_name):
                self.virsh.network_undefine(network_name)
        except LibvirtError:
            pass

    def create_network(self, job_id: str, profile_id: str) -> dict[str, Any]:
        try:
            resolve_profile(profile_id)
        except RegistryError as exc:
            raise BrokerError("broker_registry_rejected", str(exc)) from exc
        if profile_id != "isolated":
            raise BrokerError("broker_registry_rejected", f"unsupported network profile: {profile_id}")
        job_dir = self._job_dir(job_id)
        network_name = f"xentry-{job_id}"
        if self.virsh.network_exists(network_name):
            if not self.virsh.network_active(network_name):
                try:
                    self.virsh.network_start(network_name)
                except LibvirtError as exc:
                    raise BrokerError("network_create_failed", str(exc)) from exc
        else:
            active = [
                name
                for name in self.virsh.list_networks()
                if name.startswith("xentry-") and self.virsh.network_active(name)
            ]
            if active:
                raise BrokerError("preflight_refused", f"active xentry network: {active}")
            xml = network_xml(
                name=network_name,
                bridge=BRIDGE,
                target_mac=TARGET_MAC,
                target_ip=TARGET_IP,
                attacker_mac=ATTACKER_MAC,
                attacker_ip=ATTACKER_IP,
            )
            xml_path = job_dir / "network.xml"
            xml_path.write_text(xml, encoding="utf-8")
            try:
                self.virsh.network_define(xml_path)
                self.virsh.network_start(network_name)
            except LibvirtError as exc:
                raise BrokerError("network_create_failed", str(exc)) from exc
        if self.apply_nft:
            try:
                self.nft.apply(provisioning_rules(bridge=BRIDGE))
            except NftablesError as exc:
                try:
                    self.virsh.network_destroy(network_name)
                    self.virsh.network_undefine(network_name)
                except LibvirtError:
                    pass
                raise BrokerError("network_create_failed", str(exc)) from exc
        mirror_url = MIRROR_URL
        mirror_started = False
        if self.start_mirror:
            if self.manifest_path is None:
                self._cleanup_network(network_name)
                raise BrokerError("preflight_refused", "artifact mirror manifest is not configured")
            if self.mirror is None:
                try:
                    mirror = ArtifactMirror(
                        self.manifest_path,
                        bind=self.mirror_bind,
                        port=self.mirror_port,
                    )
                    mirror.start()
                    self.mirror = mirror
                except (MirrorError, OSError) as exc:
                    self._cleanup_network(network_name)
                    raise BrokerError("network_create_failed", str(exc)) from exc
            mirror_url = self.mirror.url
            mirror_started = True
        state = {
            "network_id": network_name,
            "job_id": job_id,
            "bridge": BRIDGE,
            "subnet": "10.42.0.0/24",
            "mirror_url": mirror_url,
            "mirror_started": mirror_started,
            "nft_applied": self.apply_nft,
            "created_at": _now(),
        }
        (job_dir / "network.json").write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return state

    def create_target(self, job_id: str, target_id: str, image_id: str) -> dict[str, Any]:
        try:
            resolve_target(target_id)
        except RegistryError as exc:
            raise BrokerError("broker_registry_rejected", str(exc)) from exc
        if image_id != TARGET_IMAGES[target_id]:
            raise BrokerError(
                "broker_registry_rejected",
                f"{target_id} requires image {TARGET_IMAGES[target_id]}",
            )
        return self._create_vm(
            job_id=job_id,
            role="target",
            image_id=image_id,
            resources=TARGET_PROFILES[target_id],
            mac=TARGET_MAC,
            failure_code="target_create_failed",
        )

    def create_attacker(self, job_id: str, profile_id: str, image_id: str) -> dict[str, Any]:
        try:
            resolve_profile(profile_id)
        except RegistryError as exc:
            raise BrokerError("broker_registry_rejected", str(exc)) from exc
        if profile_id != ATTACKER_PROFILE_ID:
            raise BrokerError("broker_registry_rejected", f"unsupported attacker profile: {profile_id}")
        if image_id != ATTACKER_IMAGE_ID:
            raise BrokerError(
                "broker_registry_rejected",
                f"attacker requires image {ATTACKER_IMAGE_ID}",
            )
        return self._create_vm(
            job_id=job_id,
            role="attacker",
            image_id=image_id,
            resources=ATTACKER_RESOURCES,
            mac=ATTACKER_MAC,
            failure_code="attacker_create_failed",
        )

    def _vm_state(self, vm_id: str) -> dict[str, Any] | None:
        for state_path in self.jobs_root.glob("*/*/state.json"):
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if state.get("vm_id") == vm_id:
                return state
        return None

    def place_nonce(
        self,
        vm_id: str,
        nonce_id: str,
        path: str,
        owner: str,
        mode: int,
        value: str,
    ) -> dict[str, Any]:
        if not VM_ID_RE.fullmatch(vm_id):
            raise BrokerError("broker_registry_rejected", "invalid vm_id")
        if not NONCE_RE.fullmatch(value):
            raise BrokerError("broker_registry_rejected", "invalid nonce value")
        if not path.startswith("/") or ".." in Path(path).parts:
            raise BrokerError("broker_registry_rejected", "invalid nonce path")
        if not OWNER_RE.fullmatch(owner):
            raise BrokerError("broker_registry_rejected", "invalid nonce owner")
        if not 0 <= mode <= 0o777:
            raise BrokerError("broker_registry_rejected", "invalid nonce mode")
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        key_path = self.jobs_root / str(state["job_id"]) / "keys" / "root"
        if not key_path.exists():
            raise BrokerError("nonce_place_failed", "root key is missing")
        ssh = SSHTransport(key_path, "root", str(state["guest_ip"]))
        try:
            ssh.wait(60)
            digest = ssh.place_nonce(path, owner, mode, value)
        except SSHError as exc:
            raise BrokerError("nonce_place_failed", str(exc)) from exc
        return {
            "vm_id": vm_id,
            "nonce_id": nonce_id,
            "sha256": digest,
            "path": path,
            "owner": owner,
            "mode": mode,
        }

    def _steps(self) -> StepRegistry:
        if self._step_registry is None:
            self._step_registry = StepRegistry(self.steps_manifest, self.targets_dir)
        return self._step_registry

    @staticmethod
    def _step_failure_code(step_id: str) -> str:
        if step_id.startswith("setup-"):
            return "provision_failed"
        if step_id.startswith("readiness-"):
            return "target_unhealthy"
        if step_id.startswith("build-poc-"):
            return "poc_build_failed"
        if step_id.startswith(("run-poc-", "null-")):
            return "exploit_failed"
        return "harness_error"

    def exec_step(
        self,
        vm_id: str,
        step_id: str,
        inner_params: dict[str, Any],
        tty: bool,
        timeout_s: int,
    ) -> dict[str, Any]:
        spec = self._steps().get(step_id)
        try:
            registry_step = resolve_step(step_id)
        except RegistryError as exc:
            raise BrokerError("broker_registry_rejected", str(exc)) from exc
        if spec.user not in registry_step.allowed_users:
            raise BrokerError("preflight_refused", f"step user mismatch: {step_id}")
        use_tty = tty or spec.tty
        values = self._steps().validate_params(spec, inner_params)
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        keys_dir = self.jobs_root / str(state["job_id"]) / "keys"
        root_key = keys_dir / "root"
        run_key = root_key if spec.user == "root" else keys_dir / "actor"
        local_script = spec.local_path(self.targets_dir)
        if _sha256_file(local_script) != spec.sha256:
            raise BrokerError("artifact_hash_mismatch", f"step script changed: {step_id}")
        effective_timeout = min(spec.timeout_s, timeout_s)
        prep_ssh = SSHTransport(
            root_key,
            "root",
            str(state["guest_ip"]),
            command_timeout=float(effective_timeout),
        )
        run_ssh = SSHTransport(
            run_key,
            spec.user,
            str(state["guest_ip"]),
            command_timeout=float(effective_timeout),
        )
        remote_script = f"/var/lib/xentry/steps/{step_id}.sh"
        try:
            prep_ssh.wait(60)
            prepared = prep_ssh.run("install -d -m 0755 /var/lib/xentry/steps")
            if prepared.exit_code != 0:
                raise BrokerError("provision_failed", prepared.stderr.strip())
            prep_ssh.put(local_script, remote_script)
            checked = prep_ssh.run(
                f"chmod 0755 {shlex.quote(remote_script)}; sha256sum {shlex.quote(remote_script)}"
            )
            if checked.exit_code != 0:
                raise BrokerError("provision_failed", checked.stderr.strip())
            remote_sha = checked.stdout.strip().split()[0] if checked.stdout.strip() else ""
            if remote_sha != spec.sha256:
                raise BrokerError("artifact_hash_mismatch", f"remote step script mismatch: {step_id}")
            command = f"bash {shlex.quote(remote_script)}"
            if values:
                command += " " + " ".join(shlex.quote(value) for value in values)
            result = (
                run_ssh.run_tty(command, timeout_s=float(effective_timeout))
                if use_tty
                else run_ssh.run(command)
            )
        except SSHError as exc:
            raise BrokerError(self._step_failure_code(step_id), str(exc)) from exc
        max_log = 1_000_000
        stdout = result.stdout[:max_log]
        stderr = result.stderr[:max_log]
        log_dir = self.jobs_root / str(state["job_id"]) / str(state["role"])
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        log_path = log_dir / f"exec-{step_id}-{int(time.time())}.json"
        log_path.write_text(
            json.dumps(
                {
                    "step_id": step_id,
                    "user": spec.user,
                    "exit_code": result.exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "duration_ms": result.duration_ms,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return {
            "vm_id": vm_id,
            "step_id": step_id,
            "user": spec.user,
            "exit_code": result.exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
            "duration_ms": result.duration_ms,
            "truncated": len(result.stdout) > max_log or len(result.stderr) > max_log,
            "log_path": str(log_path),
        }

    def _artifact_manifest(self) -> dict[str, dict[str, Any]]:
        if self.manifest_path is None or not self.manifest_path.exists():
            raise BrokerError("preflight_refused", "artifact manifest is missing")
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        artifacts = data.get("artifacts")
        if not isinstance(artifacts, dict):
            raise BrokerError("preflight_refused", "artifact manifest has no artifacts")
        return artifacts

    def copy_in(self, vm_id: str, artifact_id: str, guest_path: str) -> dict[str, Any]:
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        entry = self._artifact_manifest().get(artifact_id)
        if not isinstance(entry, dict) or not entry.get("path"):
            raise BrokerError("broker_registry_rejected", f"unknown artifact_id: {artifact_id}")
        local_path = Path(str(entry["path"]))
        expected = str(entry["sha256"])
        if not local_path.is_file():
            raise BrokerError("artifact_hash_mismatch", f"artifact file missing: {local_path}")
        actual = _sha256_file(local_path)
        if actual != expected:
            raise BrokerError("artifact_hash_mismatch", f"artifact hash mismatch: {artifact_id}")
        key_path = self.jobs_root / str(state["job_id"]) / "keys" / "root"
        ssh = SSHTransport(key_path, "root", str(state["guest_ip"]))
        remote = posixpath.join("/var/lib/xentry/artifacts", guest_path)
        remote_dir = posixpath.dirname(remote) or "/var/lib/xentry/artifacts"
        try:
            ssh.wait(60)
            result = ssh.run(f"install -d -m 0755 {shlex.quote(remote_dir)}")
            if result.exit_code != 0:
                raise BrokerError("provision_failed", result.stderr.strip())
            ssh.put(local_path, remote)
            result = ssh.run(f"chmod 0644 {shlex.quote(remote)}; sha256sum {shlex.quote(remote)}")
        except SSHError as exc:
            raise BrokerError("provision_failed", str(exc)) from exc
        if result.exit_code != 0:
            raise BrokerError("provision_failed", result.stderr.strip())
        remote_sha = result.stdout.strip().split()[0] if result.stdout.strip() else ""
        if remote_sha != actual:
            raise BrokerError("artifact_hash_mismatch", "remote copy hash mismatch")
        return {
            "vm_id": vm_id,
            "artifact_id": artifact_id,
            "guest_path": guest_path,
            "remote_path": remote,
            "sha256": actual,
        }

    def copy_out(self, vm_id: str, guest_path: str) -> dict[str, Any]:
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        key_path = self.jobs_root / str(state["job_id"]) / "keys" / "root"
        ssh = SSHTransport(key_path, "root", str(state["guest_ip"]))
        remote = posixpath.join("/home/xentry-guest", guest_path)
        out_root = (self.jobs_root / str(state["job_id"]) / "out").resolve()
        local = (out_root / guest_path).resolve()
        try:
            local.relative_to(out_root)
        except ValueError as exc:
            raise BrokerError("broker_registry_rejected", "invalid guest path") from exc
        local.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        try:
            ssh.wait(60)
            ssh.get(remote, local)
        except SSHError as exc:
            raise BrokerError("harness_error", str(exc)) from exc
        if not local.is_file():
            raise BrokerError("harness_error", "copy_out produced no file")
        return {
            "vm_id": vm_id,
            "artifact_id": uuid.uuid4().hex,
            "guest_path": guest_path,
            "path": str(local),
            "sha256": _sha256_file(local),
            "bytes": local.stat().st_size,
        }

    def http_probe(
        self,
        vm_id: str,
        network_id: str,
        port: int,
        method: str,
        path: str,
        timeout_s: int,
        max_bytes: int,
    ) -> dict[str, Any]:
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        if network_id != f"xentry-{state['job_id']}":
            raise BrokerError("broker_registry_rejected", "network/vm mismatch")
        guest_ip = str(state["guest_ip"])
        connection = http.client.HTTPConnection(guest_ip, port, timeout=timeout_s)
        try:
            connection.request(
                method,
                path,
                headers={"Host": f"{guest_ip}:{port}", "Connection": "close"},
            )
            response = connection.getresponse()
            body = response.read(max_bytes + 1)
            headers = {key.lower(): value for key, value in response.getheaders()}
            status = response.status
        except (OSError, http.client.HTTPException) as exc:
            raise BrokerError("probe_failed", str(exc)) from exc
        finally:
            connection.close()
        if len(body) > max_bytes:
            raise BrokerError("probe_failed", f"response exceeds {max_bytes} bytes")
        return {
            "vm_id": vm_id,
            "network_id": network_id,
            "status": status,
            "headers_sha256": hashlib.sha256(
                json.dumps(headers, sort_keys=True).encode()
            ).hexdigest(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "body_text": body.decode("utf-8", "replace"),
            "bytes": len(body),
        }

    def proxy_capture(
        self,
        vm_id: str,
        network_id: str,
        target_port: int,
        timeout_s: int,
    ) -> dict[str, Any]:
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        if network_id != f"xentry-{state['job_id']}":
            raise BrokerError("broker_registry_rejected", "network/vm mismatch")
        if state.get("role") != "target":
            raise BrokerError("broker_registry_rejected", "capture requires the target VM")
        guest_ip = str(state["guest_ip"])
        job_dir = self.jobs_root / str(state["job_id"])
        capture_dir = job_dir / "capture"
        capture_dir.mkdir(parents=True, exist_ok=True, mode=0o770)
        if self.qemu_user:
            uid, gid = (int(part) for part in self.qemu_user.split(":", 1))
            os.chown(capture_dir, uid, gid)
            os.chmod(capture_dir, 0o770)
            # QEMU opens the filter-dump path itself, so xentry-vm needs
            # execute permission on the broker-owned ancestors.
            for parent in (job_dir, self.jobs_root, self.data_dir):
                mode = parent.stat().st_mode
                os.chmod(parent, mode | 0o001)
        output_path = (capture_dir / f"capture-{uuid.uuid4().hex}.pcap").resolve()
        capture_id = output_path.stem
        object_id = f"xentrycap-{uuid.uuid4().hex[:12]}"
        interface = ""
        try:
            netdev = self.virsh.qemu_netdev(vm_id)
            interface = netdev
            self.virsh.filter_dump_add(vm_id, object_id, netdev, output_path)
            try:
                time.sleep(timeout_s)
            finally:
                try:
                    self.virsh.filter_dump_del(vm_id, object_id)
                except LibvirtError:
                    pass
            try:
                text = parse_capture(
                    output_path,
                    guest_ip,
                    attacker_ip=ATTACKER_IP,
                    target_port=target_port,
                )
            except CaptureError as exc:
                raise BrokerError("proxy_capture_failed", str(exc)) from exc
        except LibvirtError:
            # QEMU cannot attach a dump filter when vhost-net owns the tap.
            # Fall back to the tap capture; the production broker is root.
            try:
                tap = self.virsh.domain_tap(vm_id)
            except LibvirtError as exc:
                raise BrokerError("proxy_capture_failed", str(exc)) from exc
            interface = tap
            capture = ProxyCapture(tap, guest_ip, target_port, output_path)
            try:
                capture.start()
                time.sleep(timeout_s)
                capture.stop()
                text = parse_capture(
                    output_path,
                    guest_ip,
                    attacker_ip=ATTACKER_IP,
                    target_port=target_port,
                )
            except CaptureError as exc:
                raise BrokerError("proxy_capture_failed", str(exc)) from exc
        if not output_path.is_file():
            raise BrokerError("proxy_capture_failed", "capture file is missing")
        digest = _sha256_file(output_path)
        return {
            "vm_id": vm_id,
            "network_id": network_id,
            "target_ip": guest_ip,
            "target_port": target_port,
            "interface": interface,
            "capture_id": capture_id,
            "path": str(output_path),
            "sha256": digest,
            "bytes": output_path.stat().st_size,
            "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "text": text,
        }

    def read_host_evidence(self, vm_id: str, channel: str) -> dict[str, Any]:
        if channel != "org.xentry.evidence.0":
            raise BrokerError("broker_registry_rejected", f"unknown evidence channel: {channel}")
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        serial = Path(str(state.get("serial_log") or state.get("serial", "")))
        if not serial.is_file():
            serial = Path(str(state.get("serial", "")))
        if not serial.is_file():
            raise BrokerError("host_evidence_missing", "serial evidence is missing")
        try:
            data = serial.read_bytes()
        except OSError as exc:
            raise BrokerError("host_evidence_missing", str(exc)) from exc
        if not data:
            raise BrokerError("host_evidence_missing", "serial evidence is empty")
        return {
            "vm_id": vm_id,
            "channel": channel,
            "bytes_b64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }

    def _cleanup_vm_files(
        self,
        domain_name: str,
        overlay: Path,
        seed: Path,
        xml_path: Path,
    ) -> None:
        if self.virsh.domain_exists(domain_name):
            try:
                self.virsh.domain_destroy(domain_name)
            except LibvirtError:
                pass
            try:
                self.virsh.domain_undefine(domain_name)
            except LibvirtError:
                pass
        for path in (overlay, seed, xml_path):
            path.unlink(missing_ok=True)

    def snapshot(self, vm_id: str, kind: str) -> dict[str, Any]:
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        if kind not in {"disk", "memory"}:
            raise BrokerError("broker_registry_rejected", "invalid snapshot kind")
        snapshot_id = f"snap-{uuid.uuid4().hex[:12]}"
        try:
            self.virsh.snapshot_create(vm_id, snapshot_id, kind == "memory")
        except LibvirtError as exc:
            raise BrokerError("snapshot_failed", str(exc)) from exc
        return {"vm_id": vm_id, "snapshot_id": snapshot_id, "kind": kind}

    def restore(self, vm_id: str, snapshot_id: str, timeout_s: int = 300) -> dict[str, Any]:
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        try:
            self.virsh.snapshot_revert(vm_id, snapshot_id)
        except LibvirtError as exc:
            raise BrokerError("restore_failed", str(exc)) from exc
        key_path = self.jobs_root / str(state["job_id"]) / "keys" / "root"
        ssh = SSHTransport(
            key_path,
            "root",
            str(state["guest_ip"]),
            command_timeout=float(timeout_s),
        )
        try:
            ssh.wait(float(timeout_s))
        except SSHError as exc:
            raise BrokerError("restore_failed", str(exc)) from exc
        return {"vm_id": vm_id, "snapshot_id": snapshot_id}

    def reboot(self, vm_id: str, timeout_s: int) -> dict[str, Any]:
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        try:
            self.virsh.reboot(vm_id)
        except LibvirtError:
            try:
                self.virsh.domain_destroy(vm_id)
                self.virsh.domain_start(vm_id)
            except LibvirtError as exc:
                raise BrokerError("restore_failed", str(exc)) from exc
        time.sleep(2)
        key_path = self.jobs_root / str(state["job_id"]) / "keys" / "root"
        ssh = SSHTransport(
            key_path,
            "root",
            str(state["guest_ip"]),
            command_timeout=float(timeout_s),
        )
        try:
            ssh.wait(float(timeout_s))
            result = ssh.run("cat /proc/sys/kernel/random/boot_id")
        except SSHError as exc:
            raise BrokerError("restore_failed", str(exc)) from exc
        return {
            "vm_id": vm_id,
            "boot_id": result.stdout.strip(),
            "state": self.virsh.domain_state(vm_id),
        }

    def destroy_vm(self, vm_id: str) -> dict[str, Any]:
        if not VM_ID_RE.fullmatch(vm_id):
            raise BrokerError("broker_registry_rejected", "invalid vm_id")
        capture = self._serial_captures.pop(vm_id, None)
        if capture is not None:
            capture.stop()
        if self.virsh.domain_exists(vm_id):
            try:
                if self.virsh.domain_state(vm_id) != "shut off":
                    self.virsh.domain_destroy(vm_id)
            except LibvirtError:
                pass
            try:
                self.virsh.domain_undefine(vm_id)
            except LibvirtError as exc:
                raise BrokerError("teardown_failed", str(exc)) from exc
        for state_path in self.jobs_root.glob("*/*/state.json"):
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if state.get("vm_id") != vm_id:
                continue
            for key in ("overlay", "seed", "xml", "serial", "serial_log"):
                value = state.get(key)
                if value:
                    Path(str(value)).unlink(missing_ok=True)
            state_path.unlink(missing_ok=True)
        # The per-job key pair is shared by the target and attacker. Remove it
        # only after both role state files are gone; a failure mid-sweep leaves
        # the remaining VM's keys available for diagnosis and cleanup.
        for job_dir in self.jobs_root.glob("*"):
            if not job_dir.is_dir() or not (job_dir / "keys").exists():
                continue
            if not any(job_dir.glob("*/state.json")):
                shutil.rmtree(job_dir / "keys", ignore_errors=True)
        return {"destroyed": True, "vm_id": vm_id}

    def destroy_network(self, network_id: str) -> dict[str, Any]:
        if not VM_ID_RE.fullmatch(network_id):
            raise BrokerError("broker_registry_rejected", "invalid network_id")
        if self.mirror is not None:
            self.mirror.stop()
            self.mirror = None
        if self.virsh.network_exists(network_id):
            try:
                if self.virsh.network_active(network_id):
                    self.virsh.network_destroy(network_id)
                self.virsh.network_undefine(network_id)
            except LibvirtError as exc:
                raise BrokerError("teardown_failed", str(exc)) from exc
        if self.apply_nft:
            try:
                self.nft.clear()
            except NftablesError as exc:
                raise BrokerError("teardown_failed", str(exc)) from exc
        for state_path in self.jobs_root.glob("*/network.json"):
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if state.get("network_id") != network_id:
                continue
            xml_path = state_path.parent / "network.xml"
            xml_path.unlink(missing_ok=True)
            state_path.unlink(missing_ok=True)
        return {"destroyed": True, "network_id": network_id}

    def list_managed(self) -> dict[str, Any]:
        try:
            domains = [
                {"name": name, "state": self.virsh.domain_state(name)}
                for name in self.virsh.list_domains()
                if name.startswith("xentry-")
            ]
            networks = [
                {"name": name, "active": self.virsh.network_active(name)}
                for name in self.virsh.list_networks()
                if name.startswith("xentry-")
            ]
        except LibvirtError as exc:
            raise BrokerError("broker_unavailable", str(exc)) from exc
        return {"domains": domains, "networks": networks}

    def handle(self, verb: str, params: dict[str, Any]) -> dict[str, Any]:
        if verb == "create_network":
            return self.create_network(
                _text(params, "job_id"),
                _text(params, "profile_id"),
            )
        if verb == "create_target":
            return self.create_target(
                _text(params, "job_id"),
                _text(params, "target_id"),
                _text(params, "image_id"),
            )
        if verb == "create_attacker":
            return self.create_attacker(
                _text(params, "job_id"),
                _text(params, "profile_id"),
                _text(params, "image_id"),
            )
        if verb == "exec":
            inner = params.get("params", {})
            if not isinstance(inner, dict):
                raise BrokerError("broker_registry_rejected", "step params must be an object")
            forbidden = {"argv", "command", "shell", "user"} & set(inner)
            if forbidden:
                raise BrokerError(
                    "broker_registry_rejected",
                    f"raw command rejected: {sorted(forbidden)}",
                )
            tty = params.get("tty", False)
            if not isinstance(tty, bool):
                raise BrokerError("broker_registry_rejected", "invalid tty")
            return self.exec_step(
                _text(params, "vm_id"),
                _text(params, "step_id"),
                inner,
                tty,
                _integer(params, "timeout_s", 1, 3600),
            )
        if verb == "place_nonce":
            return self.place_nonce(
                _text(params, "vm_id"),
                _text(params, "nonce_id"),
                _text(params, "path", max_len=400),
                _text(params, "owner", max_len=32),
                _integer(params, "mode", 0, 0o777),
                _text(params, "value", max_len=256),
            )
        if verb == "copy_in":
            return self.copy_in(
                _text(params, "vm_id"),
                _text(params, "artifact_id"),
                _guest_path(params),
            )
        if verb == "copy_out":
            return self.copy_out(_text(params, "vm_id"), _guest_path(params))
        if verb == "http_probe":
            method = _text(params, "method", max_len=8).upper()
            if method not in {"GET", "HEAD"}:
                raise BrokerError("broker_registry_rejected", "invalid HTTP method")
            path = _text(params, "path", max_len=1024)
            if not path.startswith("/"):
                raise BrokerError("broker_registry_rejected", "invalid HTTP path")
            return self.http_probe(
                _text(params, "vm_id"),
                _text(params, "network_id"),
                _integer(params, "port", 1, 65535),
                method,
                path,
                _integer(params, "timeout_s", 1, 120),
                _integer(params, "max_bytes", 1, 1_000_000),
            )
        if verb == "proxy_capture":
            return self.proxy_capture(
                _text(params, "vm_id"),
                _text(params, "network_id"),
                _integer(params, "target_port", 1, 65535),
                _integer(params, "timeout_s", 1, 600),
            )
        if verb == "read_host_evidence":
            return self.read_host_evidence(
                _text(params, "vm_id"),
                _text(params, "channel"),
            )
        if verb == "snapshot":
            return self.snapshot(
                _text(params, "vm_id"),
                _text(params, "kind"),
            )
        if verb == "restore":
            return self.restore(
                _text(params, "vm_id"),
                _text(params, "snapshot_id"),
            )
        if verb == "reboot":
            return self.reboot(
                _text(params, "vm_id"),
                _integer(params, "timeout_s", 1, 600),
            )
        if verb == "destroy_vm":
            return self.destroy_vm(_text(params, "vm_id"))
        if verb == "destroy_network":
            return self.destroy_network(_text(params, "network_id"))
        if verb == "list_managed":
            return self.list_managed()
        raise BrokerError("broker_registry_rejected", f"runtime does not handle verb: {verb}")
