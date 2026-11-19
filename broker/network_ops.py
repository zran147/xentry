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
GATEWAY_IP = "10.42.0.1"
PROXY_PORT = 8081
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


# Everything the proxy VM must not reach once it has a route to the internet.
# Written as destinations rather than as "not the internet", because a list of
# what is forbidden can be read and checked; "the internet" cannot.
PRIVATE = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }"


def _wan_chain(
    wan_bridge: str, job_bridge: str, proxy_ip: str, proxy_ports: list[int]
) -> str:
    """Forward rules for a proxy VM that lives on its own bridge.

    Order is the whole content of this function.

    The reply rule comes FIRST because a job network is 10.42.0.0/16, which is
    inside the private set two rules below: put the drop first and the mirror
    can never answer the guest it is serving. The private drop then comes
    before the blanket accept, because that accept is what gives the proxy VM
    its internet and would otherwise hand it the operator's LAN as well.

    Nothing here accepts proxy-to-guest on a NEW connection. The mirror
    answers; it never calls.
    """
    rules = ""
    if proxy_ports:
        rules += (
            f'    iifname "{job_bridge}" oifname "{wan_bridge}" ip daddr {proxy_ip} '
            f"tcp dport {_port_set(proxy_ports)} accept\n"
        )
    return (
        rules
        + f'    iifname "{wan_bridge}" oifname "{job_bridge}" '
        "ct state established,related accept\n"
        + f'    iifname "{wan_bridge}" ip daddr {PRIVATE} drop\n'
        + f'    iifname "{wan_bridge}" accept\n'
    )


def _input_chain(bridge: str, host_services: str = "", wan_bridge: str = "") -> str:
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
        # The proxy VM may not address this host at all - not DHCP, not DNS,
        # not a port the operator forgot. It gets a static address and a public
        # resolver from cloud-init precisely so that this rule needs no
        # exception. ADR 0002 calls this the boundary: the in-VM egress filter
        # catches the accident, and root inside that VM can flush it, so this
        # is the rule that has to hold.
        # DHCP, and nothing else. The proxy VM takes its pinned address
        # from this host's dnsmasq, because the static alternative required
        # renaming a NIC and the rename left the VM unreachable. One UDP port
        # is the cost; every TCP service on this host stays closed, which is
        # the property that matters - port 8000 above all, since the app has
        # no authentication. dhclient is told to ignore the resolver dnsmasq
        # offers, so there is no DNS path to the host either.
        # The broker SSHES INTO the proxy VM to write job.json, and the VM's
        # replies arrive here, on this bridge, as input. Without this rule
        # they are dropped and every configure_mirror_vm() hangs - the job
        # bridge has had the same rule since the beginning; this bridge was
        # written without it.
        + (f'    iifname "{wan_bridge}" ct state established,related accept\n'
           f'    iifname "{wan_bridge}" udp dport 67 accept\n'
           f'    iifname "{wan_bridge}" drop\n' if wan_bridge else "")
        + "  }\n"
    )


def provisioning_rules(
    *,
    bridge: str = BRIDGE,
    gateway_ip: str = GATEWAY_IP,
    proxy_port: int = PROXY_PORT,
    table: str = TABLE,
    apt_port: int | None = None,
    registry_port: int | None = None,
    attacker_apt_port: int | None = None,
    oci_port: int | None = None,
    wan_bridge: str = "",
    proxy_ip: str = "",
) -> str:
    # Two shapes, chosen by whether a proxy VM exists.
    #
    # With proxy_ip set (ADR 0002), the mirrors are in a VM on its own bridge:
    # guest traffic crosses bridges and is policed in forward, the host offers
    # the guests NOTHING, and the input chain's service rules disappear.
    #
    # Without it, the old shape: the mirrors are root processes on this host,
    # bound to the job's gateway, so the same rule has to appear in input as
    # well as forward. Kept because a flag-day cutover on a lab with six
    # reproduced CVEs is a worse risk than one branch here, and because it
    # lets these rules ship and be tested before the VM exists.
    # One rule shape per host service, emitted into both chains: guest traffic
    # to the host gateway is delivered locally and hits input, while anything
    # else on the bridge hits forward. A service missing from either chain is
    # reachable in testing and refused in production, or the reverse.
    def service(port: int | None) -> str:
        if not port:
            return ""
        return f'    iifname "{bridge}" ip daddr {gateway_ip} tcp dport {port} accept\n'

    ports = [p for p in (proxy_port, apt_port, registry_port,
                         attacker_apt_port, oci_port) if p]
    if proxy_ip and wan_bridge:
        services = _wan_chain(wan_bridge, bridge, proxy_ip, ports)
        host_services = ""
    else:
        services = "".join(service(port) for port in ports)
        host_services = services
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
        + _input_chain(bridge, host_services, wan_bridge)
        + "}\n"
    )


def locked_rules(
    target_ports: list[int],
    *,
    bridge: str = BRIDGE,
    target_ip: str = TARGET_IP,
    attacker_ip: str = ATTACKER_IP,
    table: str = TABLE,
    wan_bridge: str = "",
    proxy_ip: str = "",
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
    # No mirrors: unreachable from here on, which is the point of the phase.
    # With a proxy VM that means NO job-to-wan rule at all - _wan_chain is
    # asked for an empty port list, so it emits only the reply rule, the
    # private drop and the proxy VM's own internet. A guest that tries to
    # fetch during the locked phase is dropped at the bridge crossing, exactly
    # as it was dropped at the host's input hook before.
    wan = (
        _wan_chain(wan_bridge, bridge, proxy_ip, [])
        if proxy_ip and wan_bridge
        else ""
    )
    body = "\n".join(rules) + "\n"
    if wan:
        body = body.replace("  }\n", wan + "  }\n", 1)
    return body + _input_chain(bridge, "", wan_bridge) + "}\n"
