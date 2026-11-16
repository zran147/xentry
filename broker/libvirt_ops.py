"""System-libvirt operations through the fixed `virsh` CLI.

The broker owns this module. Domain and network XML is generated from typed
values; callers never pass XML, command strings, or paths.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from xml.sax import saxutils


class LibvirtError(RuntimeError):
    """A virsh operation failed."""

    def __init__(self, args: list[str], stderr: str, returncode: int):
        super().__init__(f"virsh {' '.join(args)} failed ({returncode}): {stderr.strip()}")
        self.args = args
        self.stderr = stderr
        self.returncode = returncode


def _esc(value: str) -> str:
    return saxutils.escape(value, {'"': "&quot;"})


@dataclass
class Virsh:
    uri: str = "qemu:///system"
    timeout_s: int = 60

    def run(self, args: list[str], input_text: str | None = None) -> str:
        command = ["virsh", "-c", self.uri, "--quiet", *args]
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=self.timeout_s,
            check=False,
        )
        if result.returncode != 0:
            raise LibvirtError(args, result.stderr, result.returncode)
        return result.stdout

    def network_define(self, xml_path: Path) -> None:
        self.run(["net-define", str(xml_path)])

    def network_start(self, name: str) -> None:
        self.run(["net-start", name])

    def network_destroy(self, name: str) -> None:
        self.run(["net-destroy", name])

    def network_undefine(self, name: str) -> None:
        self.run(["net-undefine", name])

    def network_exists(self, name: str) -> bool:
        try:
            self.run(["net-info", name])
        except LibvirtError:
            return False
        return True

    def network_active(self, name: str) -> bool:
        try:
            output = self.run(["net-info", name])
        except LibvirtError:
            return False
        return any(line.strip() == "Active:         yes" for line in output.splitlines())

    def domain_define(self, xml_path: Path) -> None:
        self.run(["define", str(xml_path)])

    def domain_start(self, name: str) -> None:
        self.run(["start", name])

    def domain_destroy(self, name: str) -> None:
        self.run(["destroy", name])

    def domain_undefine(self, name: str) -> None:
        last: LibvirtError | None = None
        # A memory snapshot leaves snapshot metadata that blocks a plain
        # undefine. The domains are ephemeral, so discard that metadata.
        for extra in (
            ["--nvram", "--snapshots-metadata"],
            ["--snapshots-metadata"],
            [],
        ):
            try:
                self.run(["undefine", name, *extra])
                return
            except LibvirtError as exc:
                last = exc
        if last is not None:
            raise last

    def domain_exists(self, name: str) -> bool:
        try:
            self.run(["dominfo", name])
        except LibvirtError:
            return False
        return True

    def domain_state(self, name: str) -> str:
        output = self.run(["domstate", name])
        return output.strip() or "unknown"

    def domain_tap(self, name: str) -> str:
        output = self.run(["dumpxml", name])
        match = re.search(r"<target dev='(vnet[0-9]+)'", output)
        if match is None:
            raise LibvirtError(["dumpxml", name], "domain has no tap interface", 1)
        return match.group(1)

    def qemu_netdev(self, name: str) -> str:
        output = self.run(["qemu-monitor-command", name, "--hmp", "info network"])
        for line in output.splitlines():
            match = re.search(r"\s+([A-Za-z0-9_.-]+): index=\d+,type=tap", line)
            if match:
                return match.group(1)
        raise LibvirtError(
            ["qemu-monitor-command", name],
            "domain has no QEMU tap netdev",
            1,
        )

    def _qmp(self, name: str, payload: dict[str, object]) -> None:
        command = ["qemu-monitor-command", name, "--pretty", json.dumps(payload)]
        output = self.run(command)
        try:
            result = json.loads(output)
        except json.JSONDecodeError as exc:
            raise LibvirtError(command, "invalid QMP response", 1) from exc
        if isinstance(result, dict) and "error" in result:
            raise LibvirtError(command, json.dumps(result["error"]), 1)

    def filter_dump_add(self, name: str, object_id: str, netdev: str, path: Path) -> None:
        self._qmp(
            name,
            {
                "execute": "object-add",
                "arguments": {
                    "qom-type": "filter-dump",
                    "id": object_id,
                    "netdev": netdev,
                    "file": str(path),
                },
            },
        )

    def filter_dump_del(self, name: str, object_id: str) -> None:
        self._qmp(
            name,
            {"execute": "object-del", "arguments": {"id": object_id}},
        )

    def reboot(self, name: str) -> None:
        self.run(["reboot", name])

    def network_lease_ip(self, network: str, mac: str) -> str | None:
        try:
            output = self.run(["net-dhcp-leases", network])
        except LibvirtError:
            return None
        for line in output.splitlines():
            if mac.lower() not in line.lower():
                continue
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+", line)
            if match:
                return match.group(1)
        return None

    def list_domains(self) -> list[str]:
        return [line.strip() for line in self.run(["list", "--name"]).splitlines() if line.strip()]

    def list_networks(self) -> list[str]:
        return [
            line.strip()
            for line in self.run(["net-list", "--name"]).splitlines()
            if line.strip()
        ]

    def snapshot_create(self, domain: str, name: str, memory: bool) -> None:
        args = ["snapshot-create-as", domain, name]
        if memory:
            args.extend(["--memspec", "snapshot=internal"])
        else:
            args.append("--disk-only")
        self.run(args)

    def snapshot_revert(self, domain: str, name: str) -> None:
        self.run(["snapshot-revert", domain, name])


def network_xml(
    *,
    name: str,
    bridge: str,
    target_mac: str,
    target_ip: str,
    attacker_mac: str | None = None,
    attacker_ip: str | None = None,
    gateway: str = "10.42.0.1",
) -> str:
    # One /24 per job, so the range follows whichever gateway it was given.
    prefix = gateway.rsplit(".", 1)[0]
    hosts = f'      <host mac="{_esc(target_mac)}" ip="{_esc(target_ip)}"/>\n'
    if attacker_mac and attacker_ip:
        hosts += f'      <host mac="{_esc(attacker_mac)}" ip="{_esc(attacker_ip)}"/>\n'
    return (
        "<network>\n"
        f"  <name>{_esc(name)}</name>\n"
        "  <forward mode='none'/>\n"
        f"  <bridge name='{_esc(bridge)}' stp='on' delay='0'/>\n"
        f"  <ip address='{_esc(gateway)}' netmask='255.255.255.0'>\n"
        "    <dhcp>\n"
        f"      <range start='{_esc(prefix)}.100' end='{_esc(prefix)}.200'/>\n"
        f"{hosts}"
        "    </dhcp>\n"
        "  </ip>\n"
        "</network>\n"
    )


def domain_xml(
    *,
    name: str,
    memory_mb: int,
    vcpu: int,
    disk_path: Path,
    seed_path: Path,
    network_name: str,
    mac: str,
    qemu_user: str | None = None,
    serial_path: Path | None = None,
    serial_log_path: Path | None = None,
    serial_tcp_port: int | None = None,
    vhost: bool = True,
) -> str:
    seclabel = ""
    if qemu_user:
        seclabel = (
            "  <seclabel type='static' model='dac' relabel='yes'>"
            f"<label>{_esc(qemu_user)}</label></seclabel>\n"
        )
    if serial_tcp_port is not None:
        serial = (
            "    <serial type='tcp'>\n"
            f"      <source mode='bind' host='127.0.0.1' service='{serial_tcp_port}'/>\n"
            "      <protocol type='raw'/>\n"
            "      <target port='0'/>\n"
            "    </serial>\n"
        )
    elif serial_path:
        serial_log = ""
        if serial_log_path:
            serial_log = (
                f"      <log file='{_esc(str(serial_log_path))}' append='on'/>\n"
            )
        serial = (
            "    <serial type='file'>\n"
            f"      <source path='{_esc(str(serial_path))}'/>\n"
            f"{serial_log}"
            "      <target port='0'/>\n"
            "    </serial>\n"
        )
    else:
        serial = (
            "    <serial type='pty'><target port='0'/></serial>\n"
            "    <console type='pty'><target type='serial' port='0'/></console>\n"
        )
    interface_driver = "" if vhost else "      <driver name='qemu'/>\n"
    return (
        "<domain type='kvm'>\n"
        f"  <name>{_esc(name)}</name>\n"
        f"  <memory unit='MiB'>{memory_mb}</memory>\n"
        f"  <vcpu>{vcpu}</vcpu>\n"
        f"{seclabel}"
        "  <os><type arch='x86_64'>hvm</type><boot dev='hd'/></os>\n"
        "  <features><acpi/><apic/></features>\n"
        "  <devices>\n"
        "    <disk type='file' device='disk'>\n"
        "      <driver name='qemu' type='qcow2'/>\n"
        f"      <source file='{_esc(str(disk_path))}'/>\n"
        "      <target dev='vda' bus='virtio'/>\n"
        "    </disk>\n"
        "    <disk type='file' device='cdrom'>\n"
        "      <driver name='qemu' type='raw'/>\n"
        f"      <source file='{_esc(str(seed_path))}'/>\n"
        "      <target dev='sda' bus='sata'/>\n"
        "      <readonly/>\n"
        "    </disk>\n"
        "    <interface type='network'>\n"
        f"      <source network='{_esc(network_name)}'/>\n"
        f"      <mac address='{_esc(mac)}'/>\n"
        f"{interface_driver}"
        "      <model type='virtio'/>\n"
        "    </interface>\n"
        f"{serial}"
        "  </devices>\n"
        "</domain>\n"
    )
