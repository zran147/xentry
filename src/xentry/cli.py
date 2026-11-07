"""xentry CLI: cleanup and status."""

from __future__ import annotations

import argparse
import json

from xentry.broker import BrokerClient, BrokerError


def _cleanup(args: argparse.Namespace) -> int:
    client = BrokerClient(args.broker_socket) if args.broker_socket else BrokerClient()
    try:
        managed = client.call("list_managed")
    except BrokerError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, sort_keys=True))
        return 1
    domains = list(managed.get("domains") or [])
    networks = list(managed.get("networks") or [])
    print(json.dumps({"domains": domains, "networks": networks}, indent=2, sort_keys=True))
    if not args.force:
        return 0
    destroyed: list[str] = []
    failed: list[str] = []
    ordered = sorted(
        domains,
        key=lambda item: (
            0 if str(item.get("name", "")).endswith("-attacker") else 1,
            0 if str(item.get("name", "")).endswith("-target") else 1,
            str(item.get("name", "")),
        ),
    )
    for domain in ordered:
        name = str(domain.get("name", ""))
        if not name:
            continue
        try:
            client.call("destroy_vm", {"vm_id": name})
            destroyed.append(name)
        except BrokerError:
            failed.append(name)
    for network in networks:
        name = str(network.get("name", ""))
        if not name:
            continue
        try:
            client.call("destroy_network", {"network_id": name})
            destroyed.append(name)
        except BrokerError:
            failed.append(name)
    print(json.dumps({"destroyed": destroyed, "failed": failed}, indent=2, sort_keys=True))
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="xentry")
    parser.add_argument("--version", action="version", version="xentry 0.1.0")
    parser.add_argument("--broker-socket", default=None)
    sub = parser.add_subparsers(dest="command")

    cleanup = sub.add_parser("cleanup", help="inspect or force cleanup of managed resources")
    cleanup.add_argument("--status", action="store_true", help="print managed resources")
    cleanup.add_argument("--force", action="store_true", help="destroy orphan resources")

    args = parser.parse_args(argv)
    if args.command == "cleanup":
        return _cleanup(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
