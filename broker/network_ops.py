"""nftables phase rules for the isolated xentry network.

The rules drop guest forwarding by default. Provisioning allows only the
target-to-mirror path plus DHCP/DNS; the locked phase allows only the attacker
to reach the target's declared ports.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

TABLE = "xentry"
BRIDGE = "xentry0"
MIRROR_IP = "10.42.0.1"
MIRROR_PORT = 8081
TARGET_IP = "10.42.0.10"
ATTACKER_IP = "10.42.0.20"


class NftablesError(RuntimeError):
    """An nftables operation failed."""


@dataclass
class Nftables:
    timeout_s: int = 30

    def apply(self, rules: str) -> None:
        # Delete a stale table if present, then install the new phase atomically.
        self.clear()
        self._run(["-f", "-"], input_text=rules)

    def clear(self) -> None:
        self._run(["delete", "table", "inet", TABLE], check=False)

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


def provisioning_rules(
    *,
    bridge: str = BRIDGE,
    mirror_ip: str = MIRROR_IP,
    mirror_port: int = MIRROR_PORT,
) -> str:
    return (
        f"table inet {TABLE} {{\n"
        "  chain forward {\n"
        "    type filter hook forward priority 0; policy drop;\n"
        f'    iifname "{bridge}" oifname "{bridge}" ct state established,related accept\n'
        f'    iifname "{bridge}" ip daddr {mirror_ip} tcp dport {mirror_port} accept\n'
        f'    iifname "{bridge}" udp dport 67 accept\n'
        f'    iifname "{bridge}" udp dport 53 accept\n'
        f'    iifname "{bridge}" ct state established,related accept\n'
        "  }\n"
        "}\n"
    )


def locked_rules(
    target_ports: list[int],
    *,
    bridge: str = BRIDGE,
    target_ip: str = TARGET_IP,
    attacker_ip: str = ATTACKER_IP,
) -> str:
    rules = [
        f"table inet {TABLE} {{",
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
            "}",
        ]
    )
    return "\n".join(rules) + "\n"
