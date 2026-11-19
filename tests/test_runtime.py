"""Broker runtime tests with a fake libvirt backend."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
        self.tables: list[str] = []
        self.cleared = 0
        self.cleared_tables: list[str] = []

    def apply(self, rules: str, table: str = "xentry") -> None:
        self.rules.append(rules)
        self.tables.append(table)

    def clear(self, table: str = "xentry") -> None:
        self.cleared += 1
        self.cleared_tables.append(table)


def make_runtime(
    tmp_path: Path,
    *,
    manifest_path: Path | None = None,
    proxy_port: int = 8081,
    start_apt_proxy: bool = False,
    apt_port: int = 8082,
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
        proxy_port=proxy_port,
        start_apt_proxy=start_apt_proxy,
        apt_port=apt_port,
        # proxy_ip="" selects the LEGACY host-side path. Production cannot:
        # proxy_ip defaults to the proxy VM and main.py `or`s that default,
        # so no environment value re-enables this. These tests cover code
        # that is now unreachable from the real entry point, and they are
        # what will be deleted along with it.
        proxy_ip="",
    )
    return runtime, virsh, nft, image


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
        # proxy_ip="" selects the LEGACY host-side path. Production cannot:
        # proxy_ip defaults to the proxy VM and main.py `or`s that default,
        # so no environment value re-enables this. These tests cover code
        # that is now unreachable from the real entry point, and they are
        # what will be deleted along with it.
        proxy_ip="",
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


def test_each_job_gets_its_own_subnet(tmp_path: Path) -> None:
    """Two jobs on one host must not share a bridge, subnet or nft table."""
    runtime, virsh, _nft, _ = make_runtime(tmp_path)
    first = runtime.create_network("job-1", "isolated")
    second = runtime.create_network("job-2", "isolated")

    assert first["subnet"] != second["subnet"]
    assert first["bridge"] != second["bridge"]
    assert first["proxy_url"] != second["proxy_url"]
    assert {first["octet"], second["octet"]} == {1, 2}
    # Creating the second no longer tears the first down.
    assert virsh.networks["xentry-job-1"] == "active"
    assert virsh.networks["xentry-job-2"] == "active"


def test_a_job_keeps_its_subnet_across_calls(tmp_path: Path) -> None:
    runtime, _virsh, _nft, _ = make_runtime(tmp_path)
    first = runtime.create_network("job-1", "isolated")
    again = runtime.create_network("job-1", "isolated")
    assert again["octet"] == first["octet"]


def test_a_torn_down_subnet_is_reused(tmp_path: Path) -> None:
    runtime, _virsh, _nft, _ = make_runtime(tmp_path)
    first = runtime.create_network("job-1", "isolated")
    runtime.destroy_network("xentry-job-1")
    third = runtime.create_network("job-3", "isolated")
    assert third["octet"] == first["octet"]


def test_teardown_clears_only_that_job_table(tmp_path: Path) -> None:
    runtime, _virsh, nft, _ = make_runtime(tmp_path)
    runtime.create_network("job-1", "isolated")
    runtime.create_network("job-2", "isolated")
    nft.cleared_tables.clear()
    runtime.destroy_network("xentry-job-2")
    assert nft.cleared_tables == ["xentry_2"]


def test_concurrent_allocation_gives_distinct_subnets(tmp_path: Path) -> None:
    """Two workers can ask for a network at the same moment.

    Repeated, because the first version of this caught the race only about one
    run in three: network.json was written with write_text, which truncates, so
    a concurrent reader hit the empty window, failed to parse it, skipped the
    file and handed that subnet to a second job.
    """
    import threading

    for round_number in range(5):
        root = tmp_path / f"round-{round_number}"
        root.mkdir()
        runtime, _virsh, _nft, _ = make_runtime(root)
        results: dict[str, dict[str, object]] = {}
        errors: list[BaseException] = []

        # Bound as defaults: each round has its own runtime and collectors.
        def create(
            job_id: str,
            _rt: object = runtime,
            _out: dict[str, dict[str, object]] = results,
            _err: list[BaseException] = errors,
        ) -> None:
            try:
                _out[job_id] = _rt.create_network(job_id, "isolated")  # type: ignore[attr-defined]
            except BaseException as exc:  # noqa: BLE001 - reported below
                _err.append(exc)

        threads = [threading.Thread(target=create, args=(f"job-{n}",)) for n in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)

        assert not errors, errors
        octets = sorted(int(r["octet"]) for r in results.values())  # type: ignore[arg-type]
        assert octets == [1, 2, 3, 4, 5, 6], f"round {round_number}: {octets}"


# ------------------------------------------------------- pinned apt mirror ---


def test_the_catalog_is_re_read_when_it_changes(tmp_path: Path) -> None:
    """The app and the broker disagreed about the same file.

    Job a780efe5f96c failed with "image artifact is unresolved:
    debian-11-generic-image" while config/artifacts.yaml on disk said
    resolved - because the broker cached the catalog for the life of the
    process and had started before the pin went on. The form, which reads the
    file per request, offered a release the broker then refused, and the only
    cure was a restart nobody knew to do. The error blamed the artifact for
    the broker's own memory.
    """
    import yaml

    from broker.runtime import BrokerRuntime

    catalog = tmp_path / "artifacts.yaml"
    catalog.write_text(
        yaml.safe_dump({"artifacts": {"ubuntu-generic-image": {"status": "pending"}}})
    )
    images = tmp_path / "images"
    images.mkdir()
    (images / "build-results.json").write_text(json.dumps({"images": {}}))
    runtime = BrokerRuntime(
        data_dir=tmp_path,
        image_dir=images,
        catalog_path=catalog,
        # proxy_ip="" selects the LEGACY host-side path. Production cannot:
        # proxy_ip defaults to the proxy VM and main.py `or`s that default,
        # so no environment value re-enables this. These tests cover code
        # that is now unreachable from the real entry point, and they are
        # what will be deleted along with it.
        proxy_ip="",
    )
    assert runtime._catalog_data()["ubuntu-generic-image"]["status"] == "pending"

    # The operator pins it, as scripts/pin-artifact.py does.
    catalog.write_text(
        yaml.safe_dump(
            {"artifacts": {"ubuntu-generic-image": {"status": "resolved", "sha256": "a" * 64}}}
        )
    )
    # st_mtime_ns is nanoseconds, but a same-nanosecond write would be
    # indistinguishable; touch it forward to make the test deterministic.
    stamp = catalog.stat().st_mtime_ns + 1_000_000_000
    os.utime(catalog, ns=(stamp, stamp))
    assert runtime._catalog_data()["ubuntu-generic-image"]["status"] == "resolved"

    # And the build results, which a build rewrites the same way.
    (images / "build-results.json").write_text(
        json.dumps({"images": {"ubuntu-24.04-generic": {"path": "x.qcow2"}}})
    )
    stamp += 1_000_000_000
    os.utime(images / "build-results.json", ns=(stamp, stamp))
    assert "ubuntu-24.04-generic" in runtime._results_data()["images"]


def test_ping_says_which_proxies_this_process_started(tmp_path: Path) -> None:
    """XENTRY_START_OCI_MIRROR was read NOWHERE in the tree.

    BrokerRuntime took start_oci_mirror and broker/main.py never passed it, so
    every Dockerfile job failed telling the operator to set a variable that
    did nothing, however many times the broker was restarted. Nothing could
    report the truth either, so ping now answers with what this process
    actually started and /api/system shows it.
    """
    from broker.runtime import BrokerRuntime

    runtime = BrokerRuntime(
        data_dir=tmp_path, image_dir=tmp_path / "images", start_oci_mirror=True,
        # proxy_ip="" selects the LEGACY host-side path. Production cannot:
        # proxy_ip defaults to the proxy VM and main.py `or`s that default,
        # so no environment value re-enables this. These tests cover code
        # that is now unreachable from the real entry point, and they are
        # what will be deleted along with it.
        proxy_ip="",
    )
    answer = runtime.ping()
    assert answer["pong"] is True
    assert answer["oci_mirror"] is True
    assert set(answer) == {
        # "mirror" is gone: the host starts no artifact mirror any more.
        "pong", "apt_proxy", "registry_proxy", "oci_mirror",
        # The files THIS process reads, because both default to a path
        # relative to the broker's working directory and so can be a
        # different copy from the app's - which is what "image artifact is
        # unresolved: debian-11-generic-image" turned out to be, twice.
        "catalog_path", "steps_manifest",
    }
    assert answer["catalog_path"].endswith("artifacts.yaml")
    assert answer["steps_manifest"].endswith("steps.yaml")

    # And every flag BrokerRuntime accepts is passed by main.py, which is the
    # check that would have caught the original bug.
    main = Path("broker/main.py").read_text()
    accepted = {
        name
        for name in inspect.signature(BrokerRuntime.__init__).parameters
        if name.startswith("start_")
    }
    passed = set(re.findall(r"(start_\w+)=os\.environ\.get", main))
    assert accepted == passed, f"never passed: {sorted(accepted - passed)}"


def test_a_vm_disk_is_not_world_readable() -> None:
    """The ancestors are o+x so QEMU can reach its disk. The disk is not o+r.

    create_vm walks data_dir, jobs_root, job_dir and vm_dir adding 0o001,
    because QEMU runs as xentry-vm and must TRAVERSE broker-owned directories
    to open its own overlay. That is execute-only: o+r is never added, so the
    directories cannot be listed and a job id cannot be discovered from the
    filesystem.

    But qemu-img and genisoimage write their output at 0644 under root's
    umask, and nothing set a mode on them. So anyone who learned a job id -
    from the web app, which has no authentication - could traverse in and read
    the target's disk image and its cloud-init seed. QEMU owns both, so 0640
    costs it nothing.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    code = (root / "broker/runtime.py").read_text()

    block = code[code.index("if self.qemu_user:"):][:1400]
    assert "os.chmod(path, 0o640)" in block, "the overlay and seed are left at 0644"

    # Execute-only on the ancestors, never read.
    assert "parent.chmod(parent.stat().st_mode | 0o001)" in code
    assert "| 0o004" not in code, "o+r on an ancestor would make jobs enumerable"
    assert "| 0o007" not in code
    # And nothing on the HOST is chmod'd world-writable. The bare constants
    # 0o777 and 0o666 do appear, as the upper bound on the mode a caller may
    # ask for when place_nonce writes a file INSIDE a guest - a validated
    # range check, not a permission this process grants itself.
    for bad in ("0o777", "0o666", "0o757", "0o707"):
        assert f"chmod({bad}" not in code, f"host chmod to {bad}"
        assert f", {bad})" not in code.replace(f'_integer(params, "mode", 0, {bad})', ""), (
            f"host chmod to {bad}"
        )

    # The serial log was already explicit; keep it that way.
    assert re.search(r"serial\.touch\(mode=0o640", code)


def test_the_permission_document_still_describes_the_code() -> None:
    """docs/security/permission_changes.md cites file:line, which rots.

    Ten of its nineteen citations were already wrong within minutes of being
    written, because edits above them shifted the line numbers. A security
    document that points at the wrong line is worse than none: it is read as
    authoritative.

    Two things are checked. Every cited line still contains a permission
    change, and every permission change in the code is cited somewhere. The
    second half is what stops a new one being added unnoticed.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    doc_path = root / "docs/security/permission_changes.md"
    assert doc_path.is_file(), "the permission document is missing"
    doc = doc_path.read_text()

    cited: set[tuple[str, int]] = set()
    for rel, nums in re.findall(r"`((?:[a-z_]+/)+[a-z_]+\.py):(\d+(?:,\d+)*)`", doc):
        for num in nums.split(","):
            cited.add((rel, int(num)))

    wrong = []
    for rel, number in sorted(cited):
        lines = (root / rel).read_text().splitlines()
        text = lines[number - 1].strip() if number <= len(lines) else "(past end of file)"
        if not re.search(r"chmod|chown|0o[0-7]{3}", text):
            wrong.append(f"{rel}:{number} is {text[:50]!r}")
    assert not wrong, "citations no longer point at a permission change: " + "; ".join(wrong)

    # And nothing changes a mode or owner without being written down.
    actual: set[tuple[str, int]] = set()
    for rel in ("broker/runtime.py", "broker/main.py", "broker/aptproxy.py",
                "broker/ociproxy.py", "broker/registryproxy.py",
                "src/xentry/web/app.py", "src/xentry/artifact_tools.py"):
        for number, line in enumerate((root / rel).read_text().splitlines(), 1):
            if re.search(r"\.chmod\(|os\.chmod\(|os\.chown\(", line):
                actual.add((rel, number))
    undocumented = sorted(actual - cited)
    assert not undocumented, (
        "permission changes not in docs/security/permission_changes.md: "
        + ", ".join(f"{rel}:{n}" for rel, n in undocumented)
    )
