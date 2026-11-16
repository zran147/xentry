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
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import asyncssh
import yaml

from broker.aptproxy import AptProxyError, AptSnapshotProxy
from broker.errors import BrokerError
from broker.exec_ops import SSHError, SSHTransport
from broker.libvirt_ops import LibvirtError, Virsh, domain_xml, network_xml
from broker.mirror import ArtifactMirror, MirrorError
from broker.network_ops import (
    TABLE,
    Nftables,
    NftablesError,
    locked_rules,
    provisioning_rules,
)
from broker.ociproxy import OciMirror, OciProxyError
from broker.proxy import CaptureError, ProxyCapture, SerialCapture, parse_capture
from broker.registry import (
    RegistryError,
    resolve_image,
    resolve_profile,
    resolve_step,
    resolve_target,
)
from broker.registryproxy import RegistryProxy, RegistryProxyError
from broker.steps import StepRegistry

JOB_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VM_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32,128}$")
OWNER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
TARGET_MAC = "52:54:00:00:00:10"
ATTACKER_MAC = "52:54:00:00:00:20"
JOB_SUBNET_PREFIX = "10.42"


@dataclass(frozen=True)
class JobNet:
    """One job's own /24, bridge and nftables table.

    A job used to share a single bridge, subnet and table with every other, so
    only one could run at a time. Everything here is derived from one octet, so
    two jobs are on separate L2 segments: a mistake in the phase rules cannot
    let one job's attacker reach another job's target.
    """

    octet: int
    bridge: str
    gateway: str
    target_ip: str
    attacker_ip: str
    table: str
    mirror_url: str

    @classmethod
    def for_octet(cls, octet: int, mirror_port: int) -> JobNet:
        prefix = f"{JOB_SUBNET_PREFIX}.{octet}"
        return cls(
            octet=octet,
            # Bridge names are capped at 15 characters by the kernel.
            bridge=f"xentry-{octet}",
            gateway=f"{prefix}.1",
            target_ip=f"{prefix}.10",
            attacker_ip=f"{prefix}.20",
            table=f"{TABLE}_{octet}",
            mirror_url=f"http://{prefix}.1:{mirror_port}",
        )

    @property
    def subnet(self) -> str:
        return f"{JOB_SUBNET_PREFIX}.{self.octet}.0/24"


TARGET_IP = "10.42.0.10"
ATTACKER_IP = "10.42.0.20"
BRIDGE = "xentry0"
MIRROR_URL = "http://10.42.0.1:8081"
# A staged id is job-scoped and becomes a filename, so it is narrower
# than a catalog id: no dots, no slashes, no leading dash.
STAGED_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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
    # A derived target's ports are per-CVE, so none are declared here; the
    # broker decides its size, as it does for every other target.
    "generic": Resources(vcpu=2, memory_mb=4096, disk_gb=25),
    # An npm closure unpacks to roughly 3.5x its pinned size and a framework
    # build is the memory-hungry part, so this one is not the generic shape.
    "npm": Resources(vcpu=4, memory_mb=8192, disk_gb=40),
}
# Tuples: a derived target picks its release per CVE, so one target id has
# several admissible images. The app still names exactly one per job, and it
# must be one of these.
TARGET_IMAGES = {
    "php2shell": ("ubuntu-24.04-target",),
    "gitlab": ("ubuntu-24.04-target",),
    "dirtyfrag": ("ubuntu-24.04-dirtyfrag",),
    "generic": (
        "ubuntu-24.04-generic",
        "ubuntu-22.04-generic",
        "ubuntu-20.04-generic",
        "debian-11-generic",
        "ubuntu-18.04-generic",
    ),
    # The generic image, not one of its own. node comes from the job's
    # registry mirror like any other dependency, so an ecosystem target needs
    # nothing baked in - which is what stops this table growing a 2.3 GB image
    # per ecosystem.
    "npm": ("ubuntu-24.04-generic",),
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


# Step command traces are written here in the guest. copy_out resolves a
# relative guest path against /home/xentry-guest, so the trace has to live
# under that directory to be readable back out.
GUEST_TRACE_DIR = "/home/xentry-guest/.xentry-trace"
GUEST_TRACE_REL = ".xentry-trace"


def step_command(remote_script: str, values: list[str], step_id: str, trace: bool = False) -> str:
    """Build the guest shell command for a step.

    With `trace`, each command the step runs is recorded. `bash -x` alone
    writes that to stderr, which would mix it into the step's real stderr and
    into the failure message the app reports, so BASH_XTRACEFD moves it to fd 9
    and fd 9 is redirected to a file in the guest. stdout, stderr and the exit
    code are untouched. The file lives under the actor's home because copy_out
    resolves relative guest paths against it, and the guest is destroyed at
    teardown.

    Without `trace` the command is exactly what it was before tracing existed.
    The directory is created by the caller's root session, owned by the user
    the step runs as: created here instead, a root step would leave a directory
    no later unprivileged step could write its trace into, and the redirect
    would fail before the script ran.
    """
    command = f"bash {shlex.quote(remote_script)}"
    if trace:
        command = f"BASH_XTRACEFD=9 bash -x {shlex.quote(remote_script)}"
    if values:
        command += " " + " ".join(shlex.quote(value) for value in values)
    if trace:
        command += f" 9>{shlex.quote(f'{GUEST_TRACE_DIR}/{step_id}.trace')}"
    return command


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
        # Empty means "this job's gateway"; an explicit value overrides it,
        # which is how a dev host binds the mirror somewhere reachable.
        mirror_bind: str = "",
        mirror_port: int = 8081,
        # The pinned apt mirror. Off unless asked for: the three checked-in
        # targets install from baked images and need no package archive.
        start_apt_proxy: bool = False,
        apt_port: int = 8082,
        # The date-pinned registry mirror, for an ecosystem target. Off unless
        # asked for, like the apt one, and for the same reason.
        start_registry_proxy: bool = False,
        registry_port: int = 8083,
        # The attacker's own apt archive. A separate proxy, not a second
        # archive on the target's: the attacker image is Ubuntu noble and the
        # target's proxy serves one archive at one serial, which for a 2021
        # advisory is Debian sid at 20211004. Pointing noble at that would ask
        # apt to install Debian packages onto Ubuntu. The attacker's tooling is
        # not the subject of the experiment, so it takes the current serial -
        # and keeping it a separate proxy keeps each one's contract intact.
        attacker_apt_port: int = 8084,
        # Docker Hub for Debian and Ubuntu base images, when a PoC's own
        # Dockerfile is the only description of the vulnerable environment its
        # author wrote. Off unless asked for, like the others.
        start_oci_mirror: bool = False,
        oci_port: int = 8086,
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
        # One mirror per job, bound to that job's gateway: with forward=none a
        # guest on 10.42.7.0/24 cannot reach a mirror on 10.42.0.1.
        self.mirrors: dict[str, ArtifactMirror] = {}
        self.start_apt_proxy = start_apt_proxy
        self.apt_port = apt_port
        # Keyed by job like every other per-job proxy, so cleanup finds it.
        self.container_proxies: dict[str, AptSnapshotProxy] = {}
        # Shared across jobs on purpose: one snapshot, so a package fetched for
        # an earlier job is the same bytes for a later one.
        self.apt_cache = self.data_dir / "apt-cache"
        self.apt_proxies: dict[str, AptSnapshotProxy] = {}
        self.start_registry_proxy = start_registry_proxy
        self.registry_port = registry_port
        # Shared across jobs and across CVEs: the cache holds the unfiltered
        # upstream index, so a second job filters the same bytes at its own
        # cutoff and asks upstream for nothing. This is the whole reason a
        # proxy beats a per-lab closure on cost as well as on correctness.
        self.registry_cache = self.data_dir / "registry-cache"
        self.attacker_apt_port = attacker_apt_port
        self.attacker_proxies: dict[str, AptSnapshotProxy] = {}
        self.start_oci_mirror = start_oci_mirror
        self.oci_port = oci_port
        # Shared across jobs: a layer is addressed by its own digest, so the
        # same bytes are the same bytes for every job that asks.
        self.oci_cache = self.data_dir / "oci-cache"
        self.oci_mirrors: dict[str, OciMirror] = {}
        self.registry_proxies: dict[str, RegistryProxy] = {}
        self._alloc_lock = threading.Lock()
        self.steps_manifest = Path(
            steps_manifest or os.environ.get("XENTRY_STEPS_MANIFEST", "targets/steps.yaml")
        )
        self.targets_dir = Path(targets_dir or os.environ.get("XENTRY_TARGETS_DIR", "targets"))
        self._step_registry: StepRegistry | None = None
        self._catalog: dict[str, dict[str, Any]] | None = None
        # mtime of each cached file, so a pin or a build taking effect does not
        # need a broker restart nobody knew to do.
        self._stamps: dict[str, int] = {}
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

    def ping(self) -> dict[str, Any]:
        """What this PROCESS started, not what a file says.

        A flag read once at start - or, as XENTRY_START_OCI_MIRROR was, read
        nowhere in the tree - is invisible otherwise, and the job that needs
        it fails telling the operator to set something already set.
        """
        return {
            "pong": True,
            "mirror": self.start_mirror,
            "apt_proxy": self.start_apt_proxy,
            "registry_proxy": self.start_registry_proxy,
            "oci_mirror": self.start_oci_mirror,
            # The files THIS process reads. Both default to a path relative to
            # the broker's working directory, so they can silently be a
            # different copy from the app's - which is what
            # "image artifact is unresolved" turned out to be.
            "catalog_path": str(self.catalog_path.resolve()),
            "steps_manifest": str(self.steps_manifest.resolve()),
        }

    def _stale(self, path: Path, key: str) -> bool:
        """Has this file changed since it was last read into the cache?

        Both of these were cached for the life of the process, and both change
        under it: pinning an image rewrites the catalog and building one
        rewrites the results. A broker started before the pin went on
        answering "image artifact is unresolved: debian-11-generic-image"
        while the catalog on disk said resolved - blaming the artifact for the
        broker's own memory, and fixable only by a restart nobody knew to do.
        """
        try:
            stamp = path.stat().st_mtime_ns
        except OSError:
            return False
        if self._stamps.get(key) == stamp:
            return False
        self._stamps[key] = stamp
        return True

    def _catalog_data(self) -> dict[str, dict[str, Any]]:
        if not self.catalog_path.exists():
            raise BrokerError(
                "preflight_refused", f"missing artifact catalog: {self.catalog_path}"
            )
        if self._catalog is None or self._stale(self.catalog_path, "catalog"):
            # A re-pin of an image id this process already verified must be
            # verified again: the path cache short-circuits the hash check.
            self._image_cache.clear()
            data = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8")) or {}
            artifacts = data.get("artifacts")
            if not isinstance(artifacts, dict):
                raise BrokerError("preflight_refused", "artifact catalog has no artifacts")
            self._catalog = artifacts
        return self._catalog

    def _results_data(self) -> dict[str, Any]:
        path = self.image_dir / "build-results.json"
        if not path.exists():
            raise BrokerError("preflight_refused", f"missing image build results: {path}")
        if self._build_results is None or self._stale(path, "results"):
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
            # WHICH catalog. This said only "image artifact is unresolved:
            # debian-11-generic-image" and was diagnosed twice as a stale
            # cache, which it was not: the broker's WorkingDirectory is
            # /opt/xentry-broker and this path defaults to a RELATIVE
            # config/artifacts.yaml, so it read that tree's own copy - two
            # days old, ten entries, and no such image - while the app read
            # /opt/xentry/config/artifacts.yaml where the pin was.
            raise BrokerError(
                "preflight_refused",
                f"image artifact is unresolved: {artifact_id} is "
                f"{'absent from' if artifact is None else 'not resolved in'} "
                f"{self.catalog_path} ({len(self._catalog_data())} entries)",
            )
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
            # Recorded so a rebuild knows which pinned image this VM was
            # built from, without re-deriving it from the target definition.
            "image_id": image_id,
            "base_image": str(image),
            "overlay": str(overlay),
            "seed": str(seed),
            "xml": str(xml_path),
            "serial": str(serial),
            "serial_log": str(serial_log),
            "serial_tcp_port": serial_tcp_port,
            "created_at": _now(),
        }
        self._write_json(vm_dir / "state.json", state)
        return {
            "vm_id": domain_name,
            "guest_ip": guest_ip,
            "domain": domain_name,
            "role": role,
            "job_id": job_id,
        }

    def _stop_services(self, job_id: str) -> dict[str, bool]:
        """Stop every host service this job started, and say which there were.

        One place, because there are four of them now - the artifact mirror,
        the target's apt proxy, the registry proxy and the attacker's apt
        proxy - and they are started one after another: a create_network that
        failed on the fourth left the first three bound to a gateway address
        the same call then destroyed, leaving orphaned threads holding a port
        for the life of the broker with nothing to find them by.
        """
        stopped = {}
        for label, table in (
            ("mirror", self.mirrors),
            ("apt_proxy", self.apt_proxies),
            ("container_apt_proxy", self.container_proxies),
            ("registry_proxy", self.registry_proxies),
            ("attacker_apt_proxy", self.attacker_proxies),
            ("oci_mirror", self.oci_mirrors),
        ):
            service: Any = table.pop(job_id, None)
            if service is not None:
                service.stop()
            stopped[f"{label}_stopped"] = service is not None
        return stopped

    def _cleanup_network(self, network_name: str, table: str = TABLE) -> None:
        # Drop the subnet claim, or a creation that failed holds its octet for
        # the life of the host.
        job_id = network_name.removeprefix("xentry-")
        self._stop_services(job_id)
        self._net_path(job_id).unlink(missing_ok=True)
        if self.apply_nft:
            try:
                self.nft.clear(table)
            except NftablesError:
                pass
        try:
            if self.virsh.network_active(network_name):
                self.virsh.network_destroy(network_name)
            if self.virsh.network_exists(network_name):
                self.virsh.network_undefine(network_name)
        except LibvirtError:
            pass

    def create_network(
        self,
        job_id: str,
        profile_id: str,
        apt_snapshot: str = "",
        apt_archive: str = "",
        registry_cutoff: str = "",
    ) -> dict[str, Any]:
        try:
            resolve_profile(profile_id)
        except RegistryError as exc:
            raise BrokerError("broker_registry_rejected", str(exc)) from exc
        if profile_id != "isolated":
            raise BrokerError("broker_registry_rejected", f"unsupported network profile: {profile_id}")
        job_dir = self._job_dir(job_id)
        network_name = f"xentry-{job_id}"
        # A job keeps the octet it was given; a new one takes the lowest free.
        recorded = self._net(job_id)
        net = (
            recorded
            if recorded.octet
            else JobNet.for_octet(self._allocate_octet(job_id), self.mirror_port)
        )
        if self.virsh.network_exists(network_name):
            if not self.virsh.network_active(network_name):
                try:
                    self.virsh.network_start(network_name)
                except LibvirtError as exc:
                    raise BrokerError("network_create_failed", str(exc)) from exc
        else:
            xml = network_xml(
                name=network_name,
                bridge=net.bridge,
                target_mac=TARGET_MAC,
                target_ip=net.target_ip,
                attacker_mac=ATTACKER_MAC,
                attacker_ip=net.attacker_ip,
                gateway=net.gateway,
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
                self.nft.apply(
                    provisioning_rules(
                        bridge=net.bridge,
                        mirror_ip=net.gateway,
                        mirror_port=self.mirror_port,
                        table=net.table,
                        apt_port=self.apt_port if self.start_apt_proxy else None,
                        attacker_apt_port=(
                            self.attacker_apt_port if self.start_apt_proxy else None
                        ),
                        oci_port=self.oci_port if self.start_oci_mirror else None,
                        registry_port=(
                            self.registry_port if self.start_registry_proxy else None
                        ),
                    ),
                    table=net.table,
                )
            except NftablesError as exc:
                try:
                    self.virsh.network_destroy(network_name)
                    self.virsh.network_undefine(network_name)
                except LibvirtError:
                    pass
                raise BrokerError("network_create_failed", str(exc)) from exc
        mirror_url = net.mirror_url
        mirror_started = False
        if self.start_mirror:
            if self.manifest_path is None:
                self._cleanup_network(network_name, net.table)
                raise BrokerError("preflight_refused", "artifact mirror manifest is not configured")
            if job_id not in self.mirrors:
                try:
                    mirror = ArtifactMirror(
                        self.manifest_path,
                        bind=self.mirror_bind or net.gateway,
                        port=self.mirror_port,
                    )
                    mirror.start()
                    self.mirrors[job_id] = mirror
                except (MirrorError, OSError) as exc:
                    self._cleanup_network(network_name, net.table)
                    raise BrokerError("network_create_failed", str(exc)) from exc
            mirror_url = self.mirrors[job_id].url
            mirror_started = True
        apt_proxy_url = ""
        attacker_apt_proxy_url = ""
        attacker_snapshot = ""
        # Not named apt_snapshot: that is the requested serial, and a local of
        # the same name would discard it before the proxy is built.
        snapshot_used = ""
        archive_used = ""
        container_apt_host = ""
        if self.start_apt_proxy:
            if job_id not in self.apt_proxies:
                try:
                    # The app chooses the serial from the advisory date; the
                    # broker is what checks it and what inserts it into every
                    # upstream path, so the guest still cannot pick one.
                    proxy = AptSnapshotProxy(
                        self.apt_cache,
                        bind=self.mirror_bind or net.gateway,
                        port=self.apt_port,
                        serial=apt_snapshot or None,
                        archive=apt_archive or "ubuntu",
                    )
                    proxy.start()
                    self.apt_proxies[job_id] = proxy
                    # A SECOND listener on port 80, same cache and serial, for
                    # a container's apt. `docker build` takes no volume flag
                    # and the image's own sources.list is what apt reads, so
                    # the only way to point it here is to answer on the host
                    # and port that file already names: deb.debian.org:80, via
                    # --add-host. One job runs at a time, so nothing else holds
                    # 80; if something does, the dockerfile path is refused
                    # rather than the whole job.
                    try:
                        container = AptSnapshotProxy(
                            self.apt_cache,
                            bind=self.mirror_bind or net.gateway,
                            port=80,
                            serial=apt_snapshot or None,
                            archive=apt_archive or "ubuntu",
                        )
                        container.start()
                        self.container_proxies[job_id] = container
                    except (AptProxyError, OSError):
                        pass
                except AptProxyError as exc:
                    self._cleanup_network(network_name, net.table)
                    raise BrokerError("broker_registry_rejected", str(exc)) from exc
                except OSError as exc:
                    self._cleanup_network(network_name, net.table)
                    raise BrokerError("network_create_failed", str(exc)) from exc
            apt_proxy_url = self.apt_proxies[job_id].url
            held = self.container_proxies.get(job_id)
            container_apt_host = held.bind if held else ""
            # Reported so the runner records which snapshot provisioned this
            # target: without the serial, "it installed apache2" says nothing
            # about which apache2.
            snapshot_used = self.apt_proxies[job_id].serial
            # Which archive, not only which serial: the same serial means two
            # different package sets in Ubuntu and Debian.
            archive_used = self.apt_proxies[job_id].archive.name
            # The attacker's archive, beside the target's. Ubuntu at the
            # current serial, because the attacker image is noble and its
            # tooling is not what the experiment measures; the target's serial
            # is the advisory's and is frequently neither Ubuntu nor current.
            if job_id not in self.attacker_proxies:
                try:
                    attacker = AptSnapshotProxy(
                        self.apt_cache,
                        bind=self.mirror_bind or net.gateway,
                        port=self.attacker_apt_port,
                        serial=None,
                        archive="ubuntu",
                    )
                    attacker.start()
                    self.attacker_proxies[job_id] = attacker
                except (AptProxyError, OSError) as exc:
                    self._cleanup_network(network_name, net.table)
                    raise BrokerError("network_create_failed", str(exc)) from exc
            attacker_apt_proxy_url = self.attacker_proxies[job_id].url
            attacker_snapshot = self.attacker_proxies[job_id].serial
        oci_mirror_url = ""
        if self.start_oci_mirror:
            if job_id not in self.oci_mirrors:
                try:
                    # `oci`, not `mirror`: that name already holds the
                    # artifact mirror in this function, and reusing it made
                    # mypy read the two as one variable of one type.
                    oci = OciMirror(
                        self.oci_cache,
                        bind=self.mirror_bind or net.gateway,
                        port=self.oci_port,
                    )
                    oci.start()
                    self.oci_mirrors[job_id] = oci
                except (OciProxyError, OSError) as exc:
                    self._cleanup_network(network_name, net.table)
                    raise BrokerError("network_create_failed", str(exc)) from exc
            oci_mirror_url = self.oci_mirrors[job_id].url
        registry_proxy_url = ""
        cutoff_used = ""
        if self.start_registry_proxy and registry_cutoff:
            # No cutoff means no ecosystem target on this job, so no proxy: an
            # unpinned registry is the one thing this must never serve.
            if job_id not in self.registry_proxies:
                try:
                    registry = RegistryProxy(
                        self.registry_cache,
                        bind=self.mirror_bind or net.gateway,
                        port=self.registry_port,
                        cutoff=registry_cutoff,
                    )
                    registry.start()
                    self.registry_proxies[job_id] = registry
                except RegistryProxyError as exc:
                    self._cleanup_network(network_name, net.table)
                    raise BrokerError("broker_registry_rejected", str(exc)) from exc
                except OSError as exc:
                    self._cleanup_network(network_name, net.table)
                    raise BrokerError("network_create_failed", str(exc)) from exc
            registry_proxy_url = self.registry_proxies[job_id].url
            # Recorded for the same reason the apt serial is: without the date,
            # "it installed next 16.4.0" says nothing about why that version.
            cutoff_used = self.registry_proxies[job_id].cutoff
        state = {
            "network_id": network_name,
            "job_id": job_id,
            "octet": net.octet,
            "bridge": net.bridge,
            "subnet": net.subnet,
            "table": net.table,
            "gateway": net.gateway,
            "target_ip": net.target_ip,
            "attacker_ip": net.attacker_ip,
            "mirror_url": mirror_url,
            "mirror_started": mirror_started,
            "apt_proxy_url": apt_proxy_url,
            "apt_snapshot": snapshot_used,
            "apt_archive": archive_used,
            # deb822 needs the archive's own path and its own freshness rule.
            "apt_suite_path": f"/{archive_used}" if archive_used else "",
            "apt_check_valid_until": (
                self.apt_proxies[job_id].archive.check_valid_until
                if archive_used
                else True
            ),
            # Reported so the runner can provision the attacker from it, and
            # so the record says which serial armed the attacker as well as
            # which one built the target.
            "attacker_apt_proxy_url": attacker_apt_proxy_url,
            "attacker_apt_snapshot": attacker_snapshot,
            "oci_mirror_url": oci_mirror_url,
            "container_apt_host": container_apt_host,
            "registry_proxy_url": registry_proxy_url,
            "registry_cutoff": cutoff_used,
            "nft_applied": self.apply_nft,
            "created_at": _now(),
        }
        self._write_json(job_dir / "network.json", state)
        return state

    def create_target(self, job_id: str, target_id: str, image_id: str) -> dict[str, Any]:
        try:
            resolve_target(target_id)
        except RegistryError as exc:
            raise BrokerError("broker_registry_rejected", str(exc)) from exc
        allowed = TARGET_IMAGES.get(target_id)
        if not allowed or target_id not in TARGET_PROFILES:
            # resolve_target passed, so the registry and these tables disagree.
            raise BrokerError(
                "broker_registry_rejected", f"no image or profile for target: {target_id}"
            )
        if image_id not in allowed:
            raise BrokerError(
                "broker_registry_rejected",
                f"{target_id} requires one of {', '.join(allowed)}",
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

    def _net_path(self, job_id: str) -> Path:
        return self._job_dir(job_id) / "network.json"

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]) -> None:
        # Written to a sibling and renamed, because write_text truncates first.
        # A concurrent reader scanning for claimed subnets would otherwise read
        # the empty window, fail to parse it, skip the file, and hand that
        # subnet to a second job. os.replace is atomic within a directory, so a
        # reader sees either the whole old file or the whole new one.
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)

    def _allocate_octet(self, job_id: str) -> int:
        # Two workers can ask at once and the pick reads files, so the choice
        # and the claim have to happen together: an unrecorded choice is
        # invisible to the next caller, and both get the same subnet.
        with self._alloc_lock:
            octet = self._pick_octet(job_id)
            path = self._net_path(job_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._write_json(path, {"octet": octet})
            return octet

    def _pick_octet(self, job_id: str) -> int:
        # The lowest free octet, so a torn-down job's subnet comes back into
        # use. Taken means another job claims it and its network still exists.
        taken: set[int] = set()
        for path in self.jobs_root.glob("*/network.json"):
            if path.parent.name == job_id:
                continue
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                # Writes are atomic, so this is a genuinely corrupt file rather
                # than one being written right now.
                continue
            octet = state.get("octet")
            name = str(state.get("network_id") or "")
            if isinstance(octet, int) and (not name or self.virsh.network_exists(name)):
                taken.add(octet)
        for octet in range(1, 255):
            if octet not in taken:
                return octet
        raise BrokerError("network_create_failed", "no free job subnet")

    def _net(self, job_id: str) -> JobNet:
        try:
            state = json.loads(self._net_path(job_id).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
        octet = state.get("octet")
        if isinstance(octet, int):
            return JobNet.for_octet(octet, self.mirror_port)
        # A job created before per-job networks has no octet recorded, so it
        # keeps the single fixed segment it was built on.
        return JobNet(0, BRIDGE, "10.42.0.1", TARGET_IP, ATTACKER_IP, TABLE, MIRROR_URL)

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
        trace: bool = False,
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
            if trace:
                # Root makes the directory and hands it to the step's user, so
                # the redirect can create the trace file whoever the step runs
                # as.
                owned = prep_ssh.run(
                    f"install -d -m 0750 -o {shlex.quote(spec.user)} {shlex.quote(GUEST_TRACE_DIR)}"
                )
                if owned.exit_code != 0:
                    raise BrokerError("provision_failed", owned.stderr.strip())
            prep_ssh.put(local_script, remote_script)
            checked = prep_ssh.run(
                f"chmod 0755 {shlex.quote(remote_script)}; sha256sum {shlex.quote(remote_script)}"
            )
            if checked.exit_code != 0:
                raise BrokerError("provision_failed", checked.stderr.strip())
            remote_sha = checked.stdout.strip().split()[0] if checked.stdout.strip() else ""
            if remote_sha != spec.sha256:
                raise BrokerError("artifact_hash_mismatch", f"remote step script mismatch: {step_id}")
            command = step_command(remote_script, list(values), step_id, trace)
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

    def stage_artifact(
        self, job_id: str, artifact_id: str, path: str, sha256: str
    ) -> dict[str, Any]:
        """Admit one job-scoped artifact: a PoC nobody pinned in advance.

        The checked-in targets name artifacts in a catalog whose digests came
        from vendor checksums out of band. An arbitrary PoC repository has no
        such digest, so the app records the bytes it fetched and hands them
        over with their digest; the broker verifies that digest, copies the
        file into the job's own directory, and scopes the registration to that
        job. It never leaves the job's tree and never joins the global catalog,
        so one job cannot name another's artifact or shadow a pinned one.
        """
        if not JOB_ID_RE.fullmatch(job_id):
            raise BrokerError("broker_registry_rejected", "invalid job_id")
        if not STAGED_ID_RE.fullmatch(artifact_id):
            raise BrokerError("broker_registry_rejected", f"invalid artifact_id: {artifact_id}")
        if artifact_id in self._artifact_manifest():
            raise BrokerError("broker_registry_rejected", f"artifact_id is pinned: {artifact_id}")
        if not SHA256_RE.fullmatch(sha256):
            raise BrokerError("broker_registry_rejected", "invalid sha256")
        source = Path(path)
        job_dir = self._job_dir(job_id)
        # The app may only hand over a file from this job's own directory: any
        # other path would make this verb a root-privileged read of anywhere.
        try:
            resolved = source.resolve(strict=True)
            resolved.relative_to(job_dir.resolve())
        except (OSError, ValueError) as exc:
            raise BrokerError(
                "broker_registry_rejected", f"artifact is not in the job directory: {path}"
            ) from exc
        if _sha256_file(resolved) != sha256:
            raise BrokerError("artifact_hash_mismatch", f"staged artifact does not match: {path}")
        staged_dir = job_dir / "staged"
        staged_dir.mkdir(parents=True, exist_ok=True)
        staged_dir.chmod(0o750)
        target = staged_dir / artifact_id
        shutil.copyfile(resolved, target)
        target.chmod(0o640)
        self._write_json(
            job_dir / "staged.json",
            {
                **self._staged(job_id),
                artifact_id: {"path": str(target), "sha256": sha256, "staged_at": _now()},
            },
        )
        return {"artifact_id": artifact_id, "sha256": sha256, "job_id": job_id}

    def _staged(self, job_id: str) -> dict[str, Any]:
        path = self._job_dir(job_id) / "staged.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def copy_in(self, vm_id: str, artifact_id: str, guest_path: str) -> dict[str, Any]:
        state = self._vm_state(vm_id)
        if state is None:
            raise BrokerError("broker_registry_rejected", f"unknown vm_id: {vm_id}")
        # The pinned catalog first, so a staged id can never shadow one.
        entry: Any = self._artifact_manifest().get(artifact_id)
        if entry is None:
            entry = self._staged(str(state["job_id"])).get(artifact_id)
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
        # The unit runs with UMask=0077, which masks the mode handed to mkdir, so
        # the directory lands 0700 and the fetched file 0600. The app is what
        # consumes copy_out and the broker's primary group is already the app's,
        # so the modes are set explicitly here - the same reason capture_dir is
        # chmodded after its mkdir below.
        try:
            for directory in (out_root, local.parent):
                directory.chmod(0o750)
            local.chmod(0o640)
        except OSError as exc:
            raise BrokerError("harness_error", f"cannot share copy_out result: {exc}") from exc
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
                    attacker_ip=self._net(str(state["job_id"])).attacker_ip,
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
                    attacker_ip=self._net(str(state["job_id"])).attacker_ip,
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
        result: dict[str, Any] = {"destroyed": True, "vm_id": vm_id}
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
        return result

    def lock_network(self, job_id: str, target_ports: list[int]) -> dict[str, Any]:
        """Replace the provisioning ruleset with the locked one.

        Called after readiness and before any PoC code runs. Two things go away
        together: the rules that let a guest reach the host's mirror and apt
        proxy, and the services themselves. Stopping them is not redundant - it
        is what makes the guarantee hold if a rule is ever wrong, and the job
        has no further use for either.
        """
        net = self._net(job_id)
        ports = sorted({int(port) for port in target_ports})
        for port in ports:
            if port < 1 or port > 65535:
                raise BrokerError("broker_registry_rejected", f"invalid target port: {port}")
        if self.apply_nft:
            try:
                self.nft.apply(
                    locked_rules(
                        ports,
                        bridge=net.bridge,
                        target_ip=net.target_ip,
                        attacker_ip=net.attacker_ip,
                        table=net.table,
                    ),
                    table=net.table,
                )
            except NftablesError as exc:
                raise BrokerError("network_lock_failed", str(exc)) from exc
        return {
            "locked": True,
            "target_ports": ports,
            "table": net.table,
            **self._stop_services(job_id),
            "nft_applied": bool(self.apply_nft),
        }

    def destroy_network(self, network_id: str) -> dict[str, Any]:
        if not VM_ID_RE.fullmatch(network_id):
            raise BrokerError("broker_registry_rejected", "invalid network_id")
        job_id = network_id.removeprefix("xentry-")
        net = self._net(job_id)
        self._stop_services(job_id)
        if self.virsh.network_exists(network_id):
            try:
                if self.virsh.network_active(network_id):
                    self.virsh.network_destroy(network_id)
                self.virsh.network_undefine(network_id)
            except LibvirtError as exc:
                raise BrokerError("teardown_failed", str(exc)) from exc
        if self.apply_nft:
            try:
                self.nft.clear(net.table)
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
        if verb == "ping":
            return self.ping()
        if verb == "create_network":
            return self.create_network(
                _text(params, "job_id"),
                _text(params, "profile_id"),
                _text(params, "apt_snapshot") if params.get("apt_snapshot") else "",
                _text(params, "apt_archive") if params.get("apt_archive") else "",
                _text(params, "registry_cutoff") if params.get("registry_cutoff") else "",
            )
        if verb == "lock_network":
            ports = params.get("target_ports", [])
            if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
                raise BrokerError("broker_registry_rejected", "target_ports must be integers")
            if len(ports) > 16:
                raise BrokerError("broker_registry_rejected", "too many target ports")
            return self.lock_network(_text(params, "job_id"), ports)
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
        if verb == "stage_artifact":
            return self.stage_artifact(
                _text(params, "job_id"),
                _text(params, "artifact_id"),
                _text(params, "path"),
                _text(params, "sha256"),
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
            trace = params.get("trace", False)
            if not isinstance(trace, bool):
                raise BrokerError("broker_registry_rejected", "invalid trace")
            return self.exec_step(
                _text(params, "vm_id"),
                _text(params, "step_id"),
                inner,
                tty,
                _integer(params, "timeout_s", 1, 3600),
                trace,
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
