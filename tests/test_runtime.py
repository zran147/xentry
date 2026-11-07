"""Broker runtime tests with a fake libvirt backend."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import yaml

from broker.errors import BrokerError
from broker.libvirt_ops import LibvirtError
from broker.runtime import BrokerRuntime


class FakeVirsh:
    def __init__(self) -> None:
        self.networks: dict[str, str] = {}
        self.calls: list[str] = []

    def network_exists(self, name: str) -> bool:
        return name in self.networks

    def network_active(self, name: str) -> bool:
        return self.networks.get(name) == "active"

    def network_define(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8")
        name = re.search(r"<name>(.*?)</name>", text)
        assert name is not None
        self.networks[name.group(1)] = "defined"
        self.calls.append("net-define")

    def network_start(self, name: str) -> None:
        self.networks[name] = "active"
        self.calls.append("net-start")

    def network_destroy(self, name: str) -> None:
        self.networks[name] = "defined"
        self.calls.append("net-destroy")

    def network_undefine(self, name: str) -> None:
        self.networks.pop(name, None)
        self.calls.append("net-undefine")

    def list_networks(self) -> list[str]:
        return sorted(self.networks)

    def list_domains(self) -> list[str]:
        return []

    def domain_state(self, name: str) -> str:
        return "shut off"

    def domain_tap(self, name: str) -> str:
        return "vnet0"

    def qemu_netdev(self, name: str) -> str:
        raise LibvirtError(["qemu-monitor-command", name], "no netdev", 1)

    def domain_exists(self, name: str) -> bool:
        return False


class FakeNft:
    def __init__(self) -> None:
        self.rules: list[str] = []
        self.cleared = 0

    def apply(self, rules: str) -> None:
        self.rules.append(rules)

    def clear(self) -> None:
        self.cleared += 1


def make_runtime(
    tmp_path: Path,
    *,
    manifest_path: Path | None = None,
    start_mirror: bool = False,
    mirror_bind: str = "10.42.0.1",
    mirror_port: int = 8081,
) -> tuple[BrokerRuntime, FakeVirsh, FakeNft, Path]:
    image = tmp_path / "images" / "target.qcow2"
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b"test-image")
    digest = hashlib.sha256(b"test-image").hexdigest()
    catalog = tmp_path / "artifacts.yaml"
    catalog.write_text(
        yaml.safe_dump(
            {
                "artifacts": {
                    "ubuntu-target-image": {
                        "kind": "image",
                        "url": "build://ubuntu-base-image+target",
                        "sha256": digest,
                        "provenance": "test",
                        "status": "resolved",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    results = tmp_path / "images" / "build-results.json"
    results.write_text(
        json.dumps(
            {
                "images": {
                    "ubuntu-24.04-target": {
                        "path": str(image),
                        "sha256": digest,
                        "bytes": len(b"test-image"),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    virsh = FakeVirsh()
    nft = FakeNft()
    runtime = BrokerRuntime(
        tmp_path / "data",
        tmp_path / "images",
        catalog_path=catalog,
        apply_nft=True,
        virsh=virsh,
        nft=nft,
        manifest_path=manifest_path,
        start_mirror=start_mirror,
        mirror_bind=mirror_bind,
        mirror_port=mirror_port,
    )
    return runtime, virsh, nft, image


def test_create_and_destroy_network(tmp_path: Path) -> None:
    runtime, virsh, nft, _ = make_runtime(tmp_path)
    result = runtime.create_network("job-1", "isolated")
    assert result["network_id"] == "xentry-job-1"
    assert result["mirror_url"] == "http://10.42.0.1:8081"
    assert virsh.networks["xentry-job-1"] == "active"
    assert "tcp dport 8081" in nft.rules[-1]
    state = tmp_path / "data" / "jobs" / "job-1" / "network.json"
    assert state.exists()
    runtime.destroy_network("xentry-job-1")
    assert "xentry-job-1" not in virsh.networks
    assert nft.cleared == 1
    assert not state.exists()


def test_image_hash_is_verified(tmp_path: Path) -> None:
    runtime, _, _, image = make_runtime(tmp_path)
    assert runtime._image_path("ubuntu-24.04-target") == image
    image.write_bytes(b"tampered")
    fresh = BrokerRuntime(
        tmp_path / "data",
        tmp_path / "images",
        catalog_path=tmp_path / "artifacts.yaml",
        apply_nft=False,
        virsh=FakeVirsh(),
        nft=FakeNft(),
    )
    with pytest.raises(BrokerError) as exc:
        fresh._image_path("ubuntu-24.04-target")
    assert exc.value.code == "artifact_hash_mismatch"


def test_target_image_must_match_target(tmp_path: Path) -> None:
    runtime, _, _, _ = make_runtime(tmp_path)
    with pytest.raises(BrokerError) as exc:
        runtime.create_target("job-1", "php2shell", "ubuntu-24.04-attacker")
    assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError) as exc:
        runtime.create_attacker("job-1", "attacker-remote", "ubuntu-24.04-target")
    assert exc.value.code == "broker_registry_rejected"


def test_place_nonce_validation_rejects_bad_inputs(tmp_path: Path) -> None:
    runtime, _, _, _ = make_runtime(tmp_path)
    for value in ("short", "A" * 32, "g" * 32):
        with pytest.raises(BrokerError) as exc:
            runtime.place_nonce("vm-1", "nonce-1", "/root/xentry-nonce", "root", 0o600, value)
        assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError):
        runtime.place_nonce("vm-1", "nonce-1", "relative", "root", 0o600, "a" * 32)
    with pytest.raises(BrokerError):
        runtime.place_nonce("vm-1", "nonce-1", "/root/xentry-nonce", "root", 0o1000, "a" * 32)
    with pytest.raises(BrokerError) as exc:
        runtime.place_nonce("vm-1", "nonce-1", "/root/xentry-nonce", "root", 0o600, "a" * 32)
    assert exc.value.code == "broker_registry_rejected"


def test_proxy_capture_requires_the_target_and_parses_payload(tmp_path, monkeypatch) -> None:
    runtime, _, _, _ = make_runtime(tmp_path)
    vm_dir = runtime.jobs_root / "job-1" / "target"
    vm_dir.mkdir(parents=True)
    (vm_dir / "state.json").write_text(
        json.dumps(
            {
                "vm_id": "vm-1",
                "job_id": "job-1",
                "role": "target",
                "guest_ip": "10.42.0.10",
            }
        ),
        encoding="utf-8",
    )
    attacker_dir = runtime.jobs_root / "job-1" / "attacker"
    attacker_dir.mkdir()
    (attacker_dir / "state.json").write_text(
        json.dumps(
            {
                "vm_id": "vm-2",
                "job_id": "job-1",
                "role": "attacker",
                "guest_ip": "10.42.0.20",
            }
        ),
        encoding="utf-8",
    )

    class FakeCapture:
        def __init__(self, interface, target_ip, target_port, output_path):
            self.output_path = output_path
            self.interface = interface

        def start(self) -> None:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.output_path.write_bytes(b"pcap")

        def stop(self) -> None:
            return None

        def sha256(self) -> str:
            return hashlib.sha256(b"pcap").hexdigest()

    monkeypatch.setattr("broker.runtime.ProxyCapture", FakeCapture)
    monkeypatch.setattr("broker.runtime.parse_capture", lambda path, ip, **kwargs: "captured-nonce")
    monkeypatch.setattr("broker.runtime.time.sleep", lambda seconds: None)

    result = runtime.proxy_capture("vm-1", "xentry-job-1", 80, 1)
    assert result["text"] == "captured-nonce"
    assert result["interface"] == "vnet0"
    assert result["target_ip"] == "10.42.0.10"
    assert result["sha256"] == hashlib.sha256(b"pcap").hexdigest()

    def qemu_add(name: str, object_id: str, netdev: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"pcap-qemu")

    monkeypatch.setattr(runtime.virsh, "qemu_netdev", lambda name: "hostnet0")
    monkeypatch.setattr(runtime.virsh, "filter_dump_add", qemu_add, raising=False)
    monkeypatch.setattr(runtime.virsh, "filter_dump_del", lambda name, object_id: None, raising=False)
    qemu_result = runtime.proxy_capture("vm-1", "xentry-job-1", 80, 1)
    assert qemu_result["interface"] == "hostnet0"
    assert qemu_result["sha256"] == hashlib.sha256(b"pcap-qemu").hexdigest()

    with pytest.raises(BrokerError) as exc:
        runtime.proxy_capture("vm-1", "xentry-other", 80, 1)
    assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError) as exc:
        runtime.proxy_capture("vm-2", "xentry-job-1", 80, 1)
    assert exc.value.code == "broker_registry_rejected"


def test_read_host_evidence_uses_the_serial_file(tmp_path: Path) -> None:
    runtime, _, _, _ = make_runtime(tmp_path)
    serial = tmp_path / "serial.log"
    serial.write_bytes(b"host boot log")
    vm_dir = runtime.jobs_root / "job-1" / "target"
    vm_dir.mkdir(parents=True)
    (vm_dir / "state.json").write_text(
        json.dumps({"vm_id": "vm-1", "job_id": "job-1", "serial": str(serial)}),
        encoding="utf-8",
    )
    result = runtime.read_host_evidence("vm-1", "org.xentry.evidence.0")
    assert base64.b64decode(result["bytes_b64"]) == b"host boot log"
    assert result["size"] == len(b"host boot log")
    with pytest.raises(BrokerError) as exc:
        runtime.read_host_evidence("vm-1", "wrong-channel")
    assert exc.value.code == "broker_registry_rejected"


class ProbeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"probe-body"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


def test_http_probe_reads_target_body(tmp_path: Path) -> None:
    runtime, _, _, _ = make_runtime(tmp_path)
    vm_dir = runtime.jobs_root / "job-1" / "target"
    vm_dir.mkdir(parents=True)
    (vm_dir / "state.json").write_text(
        json.dumps({"vm_id": "vm-1", "job_id": "job-1", "guest_ip": "127.0.0.1"}),
        encoding="utf-8",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = runtime.http_probe(
            "vm-1", "xentry-job-1", server.server_address[1], "GET", "/", 5, 1024
        )
        assert result["status"] == 200
        assert result["body_text"] == "probe-body"
        assert len(result["body_sha256"]) == 64
    finally:
        server.shutdown()
        server.server_close()
    with pytest.raises(BrokerError) as exc:
        runtime.http_probe("vm-1", "wrong-network", 80, "GET", "/", 5, 1024)
    assert exc.value.code == "broker_registry_rejected"


def test_copy_in_guest_path_is_validated(tmp_path: Path) -> None:
    runtime, _, _, _ = make_runtime(tmp_path)
    with pytest.raises(BrokerError) as exc:
        runtime.handle(
            "copy_in",
            {"vm_id": "vm-1", "artifact_id": "php-8.4.26-src", "guest_path": "../escape"},
        )
    assert exc.value.code == "broker_registry_rejected"
    with pytest.raises(BrokerError) as exc:
        runtime.handle("copy_out", {"vm_id": "vm-1", "guest_path": "/etc/passwd"})
    assert exc.value.code == "broker_registry_rejected"


def test_runtime_starts_and_stops_mirror(tmp_path: Path) -> None:
    payload = b"mirror payload"
    artifact = tmp_path / "php.tar.xz"
    artifact.write_bytes(payload)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "artifacts": {
                    "php-8.4.26-src": {
                        "kind": "package",
                        "path": str(artifact),
                        "filename": "php.tar.xz",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    runtime, _, _, _ = make_runtime(
        tmp_path,
        manifest_path=manifest,
        start_mirror=True,
        mirror_bind="127.0.0.1",
        mirror_port=0,
    )
    result = runtime.create_network("job-1", "isolated")
    assert result["mirror_started"] is True
    assert runtime.mirror is not None
    response = httpx.get(f"{result['mirror_url']}/artifacts/php-8.4.26-src", timeout=5.0)
    assert response.content == payload
    runtime.destroy_network("xentry-job-1")
    assert runtime.mirror is None


def test_destroy_vm_removes_job_keys_after_both_roles(tmp_path: Path) -> None:
    runtime, _, _, _ = make_runtime(tmp_path)
    job_dir = runtime.jobs_root / "job-1"
    keys = job_dir / "keys"
    keys.mkdir(parents=True)
    (keys / "root").write_text("private", encoding="utf-8")
    (keys / "actor").write_text("private", encoding="utf-8")
    for role, vm_id in (("target", "vm-target"), ("attacker", "vm-attacker")):
        role_dir = job_dir / role
        role_dir.mkdir()
        overlay = role_dir / "overlay.qcow2"
        seed = role_dir / "seed.iso"
        xml = role_dir / "domain.xml"
        for path in (overlay, seed, xml):
            path.write_text("test", encoding="utf-8")
        (role_dir / "state.json").write_text(
            json.dumps(
                {
                    "vm_id": vm_id,
                    "job_id": "job-1",
                    "role": role,
                    "overlay": str(overlay),
                    "seed": str(seed),
                    "xml": str(xml),
                }
            ),
            encoding="utf-8",
        )
    runtime.destroy_vm("vm-target")
    assert keys.is_dir(), "keys must survive while the attacker state remains"
    runtime.destroy_vm("vm-attacker")
    assert not keys.exists()
    assert not any(job_dir.glob("*/state.json"))
