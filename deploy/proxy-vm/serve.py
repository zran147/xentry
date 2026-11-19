#!/usr/bin/env python3
"""The five mirrors, as one service inside the mirror VM (ADR 0002).

This file lives under deploy/ because it is deployed INTO the VM: it is not
part of the host application and it is not counted against the host's line
budget. The three proxy modules it imports are copied in beside it and import
nothing but the standard library, so this VM needs python3 and nothing else -
no venv, no wheels, no network at build time.

Configuration arrives as /etc/xentry-mirror/job.json, written by the broker
over ssh before each job and read fresh on every restart. There is no default
serial: a mirror with no pinned date would serve today's archive, which would
silently reproduce a CVE against a patched package. Missing config is a
refusal, loudly, in the journal.
"""

from __future__ import annotations

import json
import logging
import pathlib
import signal
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from broker.aptproxy import AptSnapshotProxy  # noqa: E402
from broker.ociproxy import OciMirror  # noqa: E402
from broker.registryproxy import RegistryProxy  # noqa: E402

CONFIG = pathlib.Path("/etc/xentry-mirror/job.json")
CACHE = pathlib.Path("/var/cache/xentry-mirror")
# 0.0.0.0 inside the VM. What may reach these ports is decided on the host, by
# the one rule that crosses from a job bridge to this VM's bridge, and by this
# VM's own egress filter - not by a bind address, which is the weakest of the
# three and the easiest to get wrong.
BIND = "0.0.0.0"

# EXCEPT FOR THE REGISTRY, WHICH PUTS ITS BIND ADDRESS IN WHAT IT SERVES.
#
# RegistryProxy.url is f"http://{self.bind}:{self.port}", and the pypi and npm
# filters rewrite every file URL through it - registryproxy.py:215 and :173.
# So with bind=0.0.0.0 the index told pip to fetch wheels from
#
#   http://0.0.0.0:8083/pypi/packages/...
#
# which Linux resolves to the GUEST's own loopback. pip reported
# HTTPConnectionPool(host='0.0.0.0', port=8083) ... Connection refused, and
# job d4925cca2cea died installing the attacker's toolbox after nine steps.
#
# The index request itself worked, so this was never routing or filtering: the
# bytes the mirror served named an address no guest can reach.
#
# On the host path the same code was correct by accident - bind was
# net.gateway there, a routable address. Binding here to the address the
# guests are told to use makes url correct by construction, and costs nothing:
# the firewall still decides who may connect, and 10.44.0.2 is the address the
# broker hands out (runtime.py: base = f"http://{self.proxy_ip}").
#
# apt is unaffected either way - sources.list carries the base and every index
# path is relative - which is why apt worked in that job and pip did not.
ADVERTISED = "10.44.0.2"

log = logging.getLogger("xentry-mirror")


def start(config: dict[str, object]) -> list[object]:
    serial = config.get("serial")
    archive = str(config.get("archive") or "")
    if not serial or not archive:
        raise SystemExit(
            "refusing to serve: job.json names no serial or no archive, and a "
            "mirror without a pinned date would serve today's packages - which "
            "would reproduce a CVE against a build that already carries the fix"
        )
    started: list[object] = []

    def apt(port: int, label: str, *, pinned: bool = True) -> None:
        # THE ATTACKER IS NOT PINNED, AND IS NOT DEBIAN.
        #
        # This passed the target's archive and serial to all three proxies, so
        # the attacker - an Ubuntu noble guest - was handed a Debian snapshot
        # and asked for /ubuntu/dists/noble/InRelease:
        #
        #   403 refused path for debian: /ubuntu/dists/noble/InRelease
        #   this serial predates -updates/-security: release pocket only
        #
        # The host has always done it differently (runtime.py:1118):
        # serial=None, archive="ubuntu". The attacker is a toolbox - curl,
        # socat - not evidence, so it takes the live Ubuntu archive, while
        # the target and the container runtime stay pinned to the snapshot
        # the CVE's dates demand.
        proxy = AptSnapshotProxy(
            CACHE / "apt",
            bind=BIND,
            port=port,
            serial=str(serial) if pinned else None,
            archive=archive if pinned else "ubuntu",
        )
        proxy.start()
        started.append(proxy)
        log.info(
            "%s: apt %s at %s, serial %s, port %d",
            label,
            archive if pinned else "ubuntu",
            BIND,
            serial if pinned else "unpinned",
            port,
        )

    for label, key, pinned in (
        ("target", "apt_port", True),
        ("container runtime", "container_apt_port", True),
        ("attacker", "attacker_apt_port", False),
    ):
        port = config.get(key)
        if port:
            apt(int(str(port)), label, pinned=pinned)

    port = config.get("registry_port")
    cutoff = str(config.get("cutoff") or "")
    if port and not cutoff:
        # The host has always refused this: an unpinned index would serve
        # whatever is current, and a CVE reproduced against a current package
        # is a CVE reproduced against the fix. Say so and serve the rest.
        log.warning("registry asked for with no cutoff in job.json - not serving it")
    elif port:
        registry = RegistryProxy(
            CACHE / "registry",
            bind=ADVERTISED,
            port=int(str(port)),
            cutoff=cutoff,
        )
        registry.start()
        started.append(registry)
        log.info("registry (pypi, npm, nodejs) at %s port %s, cutoff %s",
                 BIND, port, cutoff)

    port = config.get("oci_port")
    if port:
        oci = OciMirror(CACHE / "oci", bind=BIND, port=int(str(port)))
        oci.start()
        started.append(oci)
        log.info("oci mirror at %s port %s", BIND, port)

    if not started:
        raise SystemExit("refusing to serve: job.json enables no mirror at all")
    return started


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    if not CONFIG.is_file():
        raise SystemExit(f"refusing to serve: {CONFIG} does not exist")
    try:
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"refusing to serve: {CONFIG} is unreadable: {exc}") from exc
    if not isinstance(config, dict):
        raise SystemExit(f"refusing to serve: {CONFIG} is not an object")

    log.info("job %s", config.get("job_id") or "(unnamed)")
    started = start(config)
    log.info("%d mirror(s) up", len(started))

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()
    log.info("stopping")
    for proxy in started:
        shutdown = getattr(proxy, "stop", None)
        if callable(shutdown):
            shutdown()


if __name__ == "__main__":
    main()
