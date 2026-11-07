"""Libvirt XML builder tests."""

from __future__ import annotations

from pathlib import Path

from broker.libvirt_ops import LibvirtError, Virsh, domain_xml, network_xml


def test_network_xml_is_isolated_and_pins_guest_ips() -> None:
    xml = network_xml(
        name="xentry-job-1",
        bridge="xentry0",
        target_mac="52:54:00:00:00:10",
        target_ip="10.42.0.10",
        attacker_mac="52:54:00:00:00:20",
        attacker_ip="10.42.0.20",
    )
    assert "<forward mode='none'/>" in xml
    assert "<bridge name='xentry0'" in xml
    assert "<host mac=\"52:54:00:00:00:10\" ip=\"10.42.0.10\"/>" in xml
    assert "<host mac=\"52:54:00:00:00:20\" ip=\"10.42.0.20\"/>" in xml
    assert "10.42.0.1" in xml


def test_domain_xml_uses_typed_disk_seed_and_network() -> None:
    xml = domain_xml(
        name="xentry-job-1-target",
        memory_mb=2048,
        vcpu=2,
        disk_path=Path("/var/lib/xentry/job-1/target.qcow2"),
        seed_path=Path("/var/lib/xentry/job-1/seed.iso"),
        network_name="xentry-job-1",
        mac="52:54:00:00:00:10",
        qemu_user="1000:1000",
    )
    assert "<name>xentry-job-1-target</name>" in xml
    assert "<memory unit='MiB'>2048</memory>" in xml
    assert "<vcpu>2</vcpu>" in xml
    assert "<source file='/var/lib/xentry/job-1/target.qcow2'/>" in xml
    assert "<source file='/var/lib/xentry/job-1/seed.iso'/>" in xml
    assert "<source network='xentry-job-1'/>" in xml
    assert "<label>1000:1000</label>" in xml
    assert "<readonly/>" in xml


def test_domain_tap_is_read_from_libvirt_xml(monkeypatch) -> None:
    virsh = Virsh()
    monkeypatch.setattr(
        virsh,
        "run",
        lambda args: (
            "<domain><devices><interface type='network'>"
            "<target dev='vnet12'/></interface></devices></domain>"
        ),
    )
    assert virsh.domain_tap("xentry-job-target") == "vnet12"


def test_domain_undefine_discards_snapshot_metadata(monkeypatch) -> None:
    virsh = Virsh()
    calls: list[list[str]] = []

    def run(args: list[str]) -> str:
        calls.append(args)
        if args == ["undefine", "d", "--nvram", "--snapshots-metadata"]:
            raise LibvirtError(args, "cannot delete inactive domain with 1 snapshots", 1)
        return ""

    monkeypatch.setattr(virsh, "run", run)
    virsh.domain_undefine("d")
    assert calls[-1] == ["undefine", "d", "--snapshots-metadata"]


def test_qemu_netdev_and_filter_dump(monkeypatch) -> None:
    virsh = Virsh()
    calls: list[list[str]] = []

    def run(args: list[str]) -> str:
        calls.append(args)
        if "--hmp" in args:
            return "net0: index=0,type=nic,model=virtio-net-pci\n \\ hostnet0: index=0,type=tap,fd=33\n"
        return '{"return": {}}'

    monkeypatch.setattr(virsh, "run", run)
    assert virsh.qemu_netdev("d") == "hostnet0"
    virsh.filter_dump_add("d", "xentrycap", "hostnet0", Path("/tmp/x.pcap"))
    virsh.filter_dump_del("d", "xentrycap")
    payload = calls[1][-1]
    assert '"qom-type": "filter-dump"' in payload
    assert '"netdev": "hostnet0"' in payload
    assert '"file": "/tmp/x.pcap"' in payload


def test_domain_xml_can_use_tcp_serial() -> None:
    xml = domain_xml(
        name="xentry-job-1-target",
        memory_mb=1024,
        vcpu=1,
        disk_path=Path("/tmp/disk.qcow2"),
        seed_path=Path("/tmp/seed.iso"),
        network_name="xentry-job-1",
        mac="52:54:00:00:00:10",
        serial_tcp_port=47001,
    )
    assert "<serial type='tcp'>" in xml
    assert "service='47001'" in xml
    assert "<protocol type='raw'/>" in xml


def test_domain_xml_can_use_a_host_serial_file() -> None:
    xml = domain_xml(
        name="xentry-job-1-target",
        memory_mb=1024,
        vcpu=1,
        disk_path=Path("/tmp/disk.qcow2"),
        seed_path=Path("/tmp/seed.iso"),
        network_name="xentry-job-1",
        mac="52:54:00:00:00:10",
        serial_path=Path("/tmp/serial.log"),
        serial_log_path=Path("/tmp/serial-qemu.log"),
    )
    assert "<serial type='file'>" in xml
    assert "<source path='/tmp/serial.log'/>" in xml
    assert "<log file='/tmp/serial-qemu.log' append='on'/>" in xml
    assert "<console" not in xml


def test_xml_escapes_untrusted_text() -> None:
    xml = domain_xml(
        name="name<&",
        memory_mb=1024,
        vcpu=1,
        disk_path=Path("/tmp/a&b.qcow2"),
        seed_path=Path("/tmp/seed.iso"),
        network_name="net",
        mac="52:54:00:00:00:10",
    )
    assert "name&lt;&amp;" in xml
    assert "a&amp;b.qcow2" in xml
    assert "<seclabel" not in xml
