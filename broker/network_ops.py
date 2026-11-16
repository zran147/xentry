"""nftables phase rules for the isolated xentry network.

Two hooks, because the two paths a guest has are governed by different ones:

* ``forward`` sees guest-to-guest traffic across the bridge. Policy drop.
  Provisioning allows nothing between guests; the locked phase allows only the
  attacker reaching the target's declared ports.
* ``input`` sees guest-to-host traffic, because the mirror and the apt proxy
  bind the job's own gateway address - the host's address on that bridge - so
  those packets are delivered locally and never traverse ``forward`` at all.
  Provisioning allows the two host services plus DHCP/DNS; the locked phase
  allows DHCP/DNS only.

The ``input`` chain carries policy accept and ends in an explicit
``iifname <bridge> drop``. A base chain's policy applies to every packet that
reaches its hook, not only the ones its rules mention, so policy drop here would
drop the operator's own ssh to the host. Scoping every rule to the job bridge
keeps this table's reach to this job's guests.

Both phases are applied by the runtime: ``provisioning_rules`` in
create_network, ``locked_rules`` in lock_network, which the runner calls after
readiness and before any PoC code runs.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

TABLE = "xentry"
BRIDGE = "xentry0"
MIRROR_IP = "10.42.0.1"
MIRROR_PORT = 8081
APT_PORT = 8082
TARGET_IP = "10.42.0.10"
ATTACKER_IP = "10.42.0.20"


class NftablesError(RuntimeError):
    """An nftables operation failed."""


@dataclass
class Nftables:
    timeout_s: int = 30

    def apply(self, rules: str, table: str = TABLE) -> None:
        # Delete a stale table if present, then install the new phase atomically.
        # The table is per job, so one job's phase change never disturbs another.
        self.clear(table)
        self._run(["-f", "-"], input_text=rules)

    def clear(self, table: str = TABLE) -> None:
        self._run(["delete", "table", "inet", table], check=False)

    def _run(self, args: list[str], input_text: str | None = None, check: bool = True) -> None:
        try:
            result = subprocess.run(
                ["nft", *args],
                input=input_text,
                text=True,
                capture_output=True,
                timeout=self.timeout_s,
                check=False,
            )
        except OSError as exc:
            raise NftablesError(str(exc)) from exc
        if check and result.returncode != 0:
            raise NftablesError(result.stderr.strip() or f"nft exited {result.returncode}")


def _port_set(ports: list[int]) -> str:
    return "{ " + ", ".join(str(port) for port in sorted(set(ports))) + " }"


def _input_chain(bridge: str, host_services: str = "") -> str:
    # policy accept, not drop: every packet arriving anywhere on this host
    # traverses this hook, and a drop policy would take the operator's ssh with
    # it. The scoping is done by iifname on each rule plus the final drop.
    #
    # The established rule comes first and is what keeps the broker working: it
    # reaches a guest over ssh from the host, and the guest's replies arrive
    # here as input on the bridge.
    return (
        "  chain input {\n"
        "    type filter hook input priority 0; policy accept;\n"
        f'    iifname "{bridge}" ct state established,related accept\n'
        f'    iifname "{bridge}" udp dport 67 accept\n'
        f'    iifname "{bridge}" udp dport 53 accept\n'
        f"{host_services}"
        f'    iifname "{bridge}" drop\n'
        "  }\n"
    )


def provisioning_rules(
    *,
    bridge: str = BRIDGE,
    mirror_ip: str = MIRROR_IP,
    mirror_port: int = MIRROR_PORT,
    table: str = TABLE,
    apt_port: int | None = None,
    registry_port: int | None = None,
    attacker_apt_port: int | None = None,
    oci_port: int | None = None,
) -> str:
    # One rule shape per host service, emitted into both chains: guest traffic
    # to the host gateway is delivered locally and hits input, while anything
    # else on the bridge hits forward. A service missing from either chain is
    # reachable in testing and refused in production, or the reverse.
    def service(port: int | None) -> str:
        if not port:
            return ""
        return f'    iifname "{bridge}" ip daddr {mirror_ip} tcp dport {port} accept\n'

    services = (
        service(mirror_port)
        + service(apt_port)
        + service(registry_port)
        + service(attacker_apt_port)
        + service(oci_port)
    )
    return (
        f"table inet {table} {{\n"
        "  chain forward {\n"
        "    type filter hook forward priority 0; policy drop;\n"
        f'    iifname "{bridge}" oifname "{bridge}" ct state established,related accept\n'
        f"{services}"
        f'    iifname "{bridge}" udp dport 67 accept\n'
        f'    iifname "{bridge}" udp dport 53 accept\n'
        f'    iifname "{bridge}" ct state established,related accept\n'
        "  }\n"
        + _input_chain(bridge, services)
        + "}\n"
    )


def locked_rules(
    target_ports: list[int],
    *,
    bridge: str = BRIDGE,
    target_ip: str = TARGET_IP,
    attacker_ip: str = ATTACKER_IP,
    table: str = TABLE,
) -> str:
    rules = [
        f"table inet {table} {{",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        f'    iifname "{bridge}" oifname "{bridge}" ct state established,related accept',
    ]
    if target_ports:
        rules.append(
            f'    iifname "{bridge}" ip saddr {attacker_ip} ip daddr {target_ip} '
            f"tcp dport {_port_set(target_ports)} accept"
        )
    rules.extend(
        [
            f'    iifname "{bridge}" udp dport 67 accept',
            f'    iifname "{bridge}" udp dport 53 accept',
            "  }",
        ]
    )
    # No host services: the mirror and the apt proxy are unreachable from here
    # on, which is the point of the phase.
    return "\n".join(rules) + "\n" + _input_chain(bridge) + "}\n"
