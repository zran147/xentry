"""Host rules for the proxy VM (ADR 0002, stage 1).

These are pure string builders, so they can be checked exactly - which is
worth doing, because the failure mode of one wrong line is a VM with a quiet
route to the operator's LAN, and the failure mode of another is a job that
cannot install anything. Only the first is silent.
"""

from __future__ import annotations

from broker.network_ops import PRIVATE, locked_rules, provisioning_rules

WAN = "xentrywan0"
JOB = "xentry0"
PROXY = "10.44.0.2"


def _forward(rules: str) -> list[str]:
    body = rules[rules.index("chain forward") : rules.index("chain input")]
    return [line.strip() for line in body.splitlines() if line.strip().startswith("iifname")]


def _input(rules: str) -> list[str]:
    body = rules[rules.index("chain input") :]
    return [line.strip() for line in body.splitlines() if line.strip().startswith("iifname")]


def test_the_guests_are_offered_nothing_by_the_host() -> None:
    """The reason for the whole exercise.

    Before this, a guest fetching a package opened a TCP connection to a root
    process on the host, and the input chain had to carry a rule per mirror.
    With the mirrors in a VM the host serves DHCP and DNS and nothing else.
    """
    rules = provisioning_rules(
        bridge=JOB, apt_port=8082, registry_port=8083, oci_port=8086,
        wan_bridge=WAN, proxy_ip=PROXY,
    )
    served = [line for line in _input(rules) if "tcp dport" in line]
    assert served == [], served
    # DHCP and DNS only, then the drop.
    assert any("udp dport 67" in line for line in _input(rules))
    assert any("udp dport 53" in line for line in _input(rules))
    assert f'iifname "{JOB}" drop' in _input(rules)


def test_the_proxy_vm_reaches_the_host_on_one_udp_port_and_nothing_else() -> None:
    """ADR 0002 wanted no exception. There is exactly one, and it is DHCP.

    The static alternative required cloud-init to rename the NIC, and the
    rename left the VM answering nothing - no ARP, no ping, no ssh - while
    libvirt's lease table showed DHCP had worked perfectly before it. So the
    address is pinned by libvirt and the VM speaks DHCP to the host.

    What that costs is one UDP port. What it does not cost is any TCP service
    on the host: ssh, the broker socket, and port 8000 - the app, which has no
    authentication - all stay unreachable. dhclient is told to supersede the
    resolver dnsmasq offers, so there is no DNS path either.

    The in-VM filter catches the accident, but root inside that VM can flush
    its own ruleset, so this is the rule that has to hold.
    """
    for rules in (
        provisioning_rules(bridge=JOB, apt_port=8082, wan_bridge=WAN, proxy_ip=PROXY),
        locked_rules([8080], bridge=JOB, wan_bridge=WAN, proxy_ip=PROXY),
    ):
        inbound = _input(rules)
        assert f'iifname "{WAN}" drop' in inbound
        before = inbound[: inbound.index(f'iifname "{WAN}" drop')]
        allowed = [line for line in before if WAN in line and "accept" in line]
        # One rule, DHCP only. No TCP, and no DNS.
        assert allowed == [
        f'iifname "{WAN}" ct state established,related accept',
        f'iifname "{WAN}" udp dport 67 accept',
    ], allowed
        assert not [line for line in inbound if WAN in line and "tcp" in line]
        assert not [line for line in inbound
                    if WAN in line and "dport 53" in line]


def test_the_reply_rule_precedes_the_private_drop() -> None:
    """A job network is 10.43.0.0/16, which is inside 10.0.0.0/8.

    Put the private drop first and the mirror can never answer the guest it
    exists to serve: every reply packet is addressed into that range. This is
    the ordering bug this test exists to catch, and it would present as "apt
    hangs" rather than as anything about firewalls.
    """
    rules = provisioning_rules(
        bridge=JOB, apt_port=8082, wan_bridge=WAN, proxy_ip=PROXY
    )
    lines = _forward(rules)
    reply = next(i for i, line in enumerate(lines)
                 if line.startswith(f'iifname "{WAN}" oifname "{JOB}"'))
    drop = next(i for i, line in enumerate(lines)
                if line.startswith(f'iifname "{WAN}" ip daddr'))
    accept = next(i for i, line in enumerate(lines)
                  if line == f'iifname "{WAN}" accept')
    assert reply < drop < accept, lines
    assert "10.0.0.0/8" in PRIVATE
    assert "192.168.0.0/16" in PRIVATE


def test_the_proxy_vm_never_opens_a_connection_to_a_guest() -> None:
    """It answers; it does not call.

    Only established,related crosses from the wan bridge into a job bridge, so
    a compromised mirror cannot reach into the target or the attacker.
    """
    rules = provisioning_rules(
        bridge=JOB, apt_port=8082, wan_bridge=WAN, proxy_ip=PROXY
    )
    crossings = [line for line in _forward(rules)
                 if line.startswith(f'iifname "{WAN}" oifname "{JOB}"')]
    assert crossings, _forward(rules)
    for line in crossings:
        assert "ct state established,related" in line


def test_the_locked_phase_lets_a_guest_fetch_nothing() -> None:
    """The phase model, unchanged in substance.

    The provisioning phase accepts job-to-proxy on the mirror ports. The
    locked phase has no such rule at all, so a PoC cannot reach an archive -
    it is dropped at the bridge crossing now instead of at the host's input
    hook, which is the same guarantee in a different place.
    """
    locked = locked_rules([8080], bridge=JOB, wan_bridge=WAN, proxy_ip=PROXY)
    assert not [line for line in _forward(locked)
                if line.startswith(f'iifname "{JOB}" oifname "{WAN}"')]
    # The attacker's one permitted path survives.
    assert any("ip saddr" in line and "tcp dport { 8080 }" in line
               for line in _forward(locked))
    # And the proxy VM keeps its own internet, which costs the guests nothing.
    assert f'iifname "{WAN}" accept' in _forward(locked)

    provisioning = provisioning_rules(
        bridge=JOB, apt_port=8082, wan_bridge=WAN, proxy_ip=PROXY
    )
    assert [line for line in _forward(provisioning)
            if line.startswith(f'iifname "{JOB}" oifname "{WAN}"')]


def test_without_a_proxy_vm_the_old_shape_is_unchanged() -> None:
    """Both halves of the cutover, so this can ship before the VM exists.

    A lab with six reproduced CVEs is not worth a flag day. With no proxy_ip
    the rules are exactly what they were: the mirrors are host processes bound
    to the job's gateway, so each service appears in input as well as forward.
    """
    rules = provisioning_rules(bridge=JOB, apt_port=8082, registry_port=8083)
    served = [line for line in _input(rules) if "tcp dport" in line]
    assert len(served) == 3, served          # proxy_port, apt, registry
    assert WAN not in rules
    assert PRIVATE not in rules
    for line in served:
        assert "ip daddr 10.42.0.1" in line  # the host's own gateway address


def test_there_is_no_longer_a_way_back_to_the_host_mirrors() -> None:
    """The switch is gone. The proxy VM is the only path.

    proxy_ip defaulted to "" while the mirrors still ran on the host, so the
    OLD path was what actually ran unless an environment variable said
    otherwise - and a job submitted to test the new path ran the old one and
    proved nothing. That is the bug this test exists to prevent returning.

    Two things make it unreachable now: the runtime defaults proxy_ip to the
    VM, and main.py `or`s that default, so an empty value in the env file
    resolves to the VM rather than to the host.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    runtime_src = (root / "broker/runtime.py").read_text()
    main_src = (root / "broker/main.py").read_text()

    assert 'PROXY_VM_IP = "10.44.0.2"' in runtime_src
    assert "proxy_ip: str = PROXY_VM_IP" in runtime_src
    # `or`, not a bare default: an empty value must not select the host path.
    assert 'os.environ.get("XENTRY_PROXY_IP") or PROXY_VM_IP' in main_src
    # XENTRY_WAN_BRIDGE is gone. It reached only the rule builders, which the
    # runtime no longer calls; the bridge name is fixed in host-wan.nft.
    assert "XENTRY_WAN_BRIDGE" not in main_src
    assert 'os.environ.get("XENTRY_PROXY_IP", "")' not in main_src
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    # The gates themselves stay: they are what makes the host-side code
    # unreachable rather than deleted, and the tests that still exercise it
    # pass proxy_ip="" explicitly to say so.
    code = "\n".join(
        line for line in runtime_src.splitlines()
        if not line.strip().startswith("#")
    )
    # These were once gates - `start_mirror and not self.proxy_ip` and three
    # like it - which proved the old path could not run. The gated code has
    # since been deleted outright, which is the stronger statement: there is no
    # host-side mirror to fall back to, gated or otherwise.
    for gone in ("self.start_mirror and not self.proxy_ip",
                 "self.start_apt_proxy and not self.proxy_ip",
                 "self.start_oci_mirror and not self.proxy_ip",
                 "self.start_registry_proxy and registry_cutoff and not self.proxy_ip",
                 # and the constructors those gates guarded
                 "ArtifactMirror(",
                 "AptSnapshotProxy(",
                 "OciMirror(",
                 "RegistryProxy("):
        assert gone not in code, f"the host-side path is back: {gone}"
    # wan_bridge was only ever passed to those rule builders, so removing them
    # left XENTRY_WAN_BRIDGE read by nothing. The bridge name is fixed in
    # deploy/proxy-vm/host-wan.nft, which is a static ruleset.
    assert "self.wan_bridge" not in code
    assert "XENTRY_WAN_BRIDGE" not in (
        pathlib.Path(__file__).resolve().parents[1] / "broker/main.py"
    ).read_text()


def test_a_mirror_vm_that_will_not_come_up_fails_the_job() -> None:
    """Carrying on would reproduce a CVE against the wrong archive.

    The proxy VM is persistent, so a failed reconfiguration leaves it holding
    the PREVIOUS job's serial. Serving that silently is the worst outcome
    available: the job would pass, against packages dated to someone else's
    advisory.
    """
    import pathlib

    runtime = (
        pathlib.Path(__file__).resolve().parents[1] / "broker/runtime.py"
    ).read_text()
    body = runtime[runtime.index("def configure_mirror_vm") : runtime.index("def _cleanup_network")]

    assert "if not self.proxy_ip:" in body and "return" in body
    assert body.count('BrokerError(\n                "proxy_vm_unconfigured"') == 2
    # The journal is carried into the failure, not left on the VM.
    assert "journalctl -u xentry-proxy.service" in body
    assert "install -D -m 0644 /dev/stdin /etc/xentry-mirror/job.json" in body

    # Configuration goes over ssh, never a port a guest could reach. The ssh
    # itself now lives in _proxy_run, shared with set_phase.
    runner = runtime[runtime.index("def _proxy_run") : runtime.index("def set_phase")]
    assert '"ssh", "-i", self.proxy_key' in runner
    assert "capture_output=True" in runner and "timeout=120" in runner


def test_what_the_vm_runs_works_on_the_base_image_s_python() -> None:
    """"Standard library only" was true and not enough.

    The install asserts these modules import nothing outside
    sys.stdlib_module_names - which validates module NAMES and says nothing
    about the Python VERSION they need. The VM is Debian 11, so python3.9,
    and registryproxy.py had

        from datetime import UTC

    added in 3.11. The import failed inside the VM and took the whole mirror
    service down, so a job failed at create_network with a traceback about
    datetime - four layers from anything a reader would connect to a version.

    Two checks, because they catch different things: ast.parse with
    feature_version sees syntax, and a name list sees runtime additions.
    """
    import ast
    import pathlib

    # Added after 3.9, by the version that added them.
    LATER = {
        "datetime.UTC": "3.11",
        "from datetime import UTC": "3.11",
        "ExceptionGroup": "3.11",
        "tomllib": "3.11",
        "StrEnum": "3.11",
        "typing.Self": "3.11",
        "asyncio.TaskGroup": "3.11",
        "hashlib.file_digest": "3.11",
        "itertools.batched": "3.12",
        "typing.override": "3.12",
    }
    root = pathlib.Path(__file__).resolve().parents[1]
    files = [root / "broker" / f"{n}.py"
             for n in ("aptproxy", "ociproxy", "registryproxy")]
    files.append(root / "deploy/proxy-vm/serve.py")

    for path in files:
        src = path.read_text()
        # Syntax the base image's interpreter must accept.
        ast.parse(src, feature_version=(3, 9))
        # Names it will not have. Comments stripped, or the comment explaining
        # the UTC fix matches the check for UTC.
        code = "\n".join(
            l for l in src.splitlines() if not l.strip().startswith("#")
        )
        for name, version in LATER.items():
            assert name not in code, f"{path.name} uses {name}, added in {version}"


def test_the_vm_side_refuses_to_serve_an_unpinned_archive() -> None:
    """deploy/proxy-vm/serve.py, which is not counted against the budget.

    A mirror with no serial serves today's packages, and a CVE reproduced
    against today's packages is a CVE reproduced against a build that already
    carries the fix - a false negative indistinguishable from a working job.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "deploy/proxy-vm"
    serve = (root / "serve.py").read_text()
    code = "\n".join(
        line for line in serve.splitlines() if not line.strip().startswith("#")
    )
    assert "if not serial or not archive:" in code
    assert "raise SystemExit" in code
    assert 'raise SystemExit(f"refusing to serve: {CONFIG} does not exist")' in code

    # The egress filter must accept replies BEFORE it drops private
    # destinations: this VM has one NIC and the guests it serves are
    # 10.43.0.0/16, so every reply it sends is addressed into a private range.
    # The first version had the drop first, which would have blocked every
    # mirror answer - the same ordering bug the host rules have a test for.
    nft = (root / "firewall.nft").read_text()
    lines = [l.strip() for l in nft.splitlines()
             if l.strip() and not l.strip().startswith("#")]
    out = lines[lines.index("chain output {") : lines.index("chain input {")]
    established = next(i for i, l in enumerate(out)
                       if l == "ct state established,related accept")
    host_drop = next(i for i, l in enumerate(out) if l == "ip daddr 10.44.0.1 drop")
    private = next(i for i, l in enumerate(out)
                   if l.startswith("ip daddr {") and l.endswith("drop"))
    assert established < host_drop < private, out
    # And no interface is named: the NIC name was a guess about PCI slots, and
    # a rule naming an interface that does not exist filters nothing.
    #
    # Against `lines`, not `nft`: the comment that explains the removal
    # contains the word, which is the sixth time today a check has matched its
    # own explanation. Comments are stripped before asserting, always.
    rules = "\n".join(lines)
    assert "enp1s0" not in rules
    assert "oifname" not in rules

    # SSH must not depend on conntrack, in either direction. Loading this
    # ruleset is what loads nf_conntrack, so the session doing the loading is
    # not yet tracked: a state-only allowance drops it and the load hangs.
    out = lines[lines.index("chain output {") : lines.index("chain input {")]
    inp = lines[lines.index("chain input {"):]
    assert out.index("tcp sport 22 accept") < out.index(
        "ct state established,related accept"
    ), out
    # The dead-man rule on the way in. It used to be an unconditional
    # `tcp dport 22 accept`, which also let a GUEST reach the jumphost; it is
    # now a source match on this host, which keeps the property that matters
    # here - it does not depend on conntrack state, so the session that loads
    # the ruleset survives loading it - while reaching nobody else.
    assert "ip saddr 10.44.0.1 accept" in inp, inp
    assert "tcp dport 22 accept" not in inp, inp

    # The unit will not start without the filter loaded.
    unit = (root / "xentry-proxy.service").read_text()
    assert "Requires=nftables.service" in unit
    assert "[Install]" in unit

    # The probe checks the port that matters most: the unauthenticated app.
    probe = (root / "isolation-probe.sh").read_text()
    assert "8000" in probe
    assert "192.168.137.10" in probe and "192.168.136.1" in probe


def test_the_host_keeps_permanent_rules_for_that_bridge() -> None:
    """The per-job table is cleared between jobs. The VM is not.

    runtime.py applies the `xentry` table in create_network and clears it in
    cleanup, so between jobs it does not exist - and the rule that stops the
    proxy VM reaching this host lived in it. The VM is persistent and has
    internet access, so for most of its life nothing on the host stood
    between it and port 8000, where the app answers without authentication.

    A persistent VM needs a persistent rule, in a table of its own so the two
    never collide.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "deploy/proxy-vm"
    nft = (root / "host-wan.nft").read_text()
    rules = [l.strip() for l in nft.splitlines()
             if l.strip() and not l.strip().startswith("#")]

    # Its own table, and it must never touch the per-job one. Checked against
    # `rules` (comments stripped): the prose explaining this names the per-job
    # table, and an assertion on the raw text matches its own explanation -
    # the eighth time that has happened today.
    assert "table inet xentry_wan {" in rules
    assert not [l for l in rules if l.startswith(("table inet xentry ",
                                                  "delete table inet xentry ",
                                                  "flush table inet xentry "))]

    inp = rules[rules.index("chain input {"):rules.index("chain forward {")]
    # Replies to the broker's ssh, DHCP, then everything else dropped.
    assert 'iifname "xentrywan0" ct state established,related accept' in inp
    assert 'iifname "xentrywan0" udp dport 67 accept' in inp
    assert 'iifname "xentrywan0" drop' in inp
    assert not [l for l in inp if "tcp" in l]
    # Last RULE, not last line: the list carries the closing brace too.
    matched = [l for l in inp if l.startswith("iifname")]
    assert matched[-1] == 'iifname "xentrywan0" drop', matched

    fwd = rules[rules.index("chain forward {"):]
    # policy accept, or it would fight the per-job table's own forward chain.
    assert any("policy accept" in l for l in fwd), fwd
    # The operator's LAN and the host's docker bridge, by name.
    for blocked in ("192.168.136.0/23", "172.16.0.0/12", "169.254.0.0/16"):
        assert [l for l in fwd if blocked in l and l.endswith("drop")], blocked
    # And no NEW connection from the mirror into a job network.
    assert [l for l in fwd if "oifname \"xentry*\"" in l and "ct state new drop" in l]

    # A unit, or the rules are gone after a reboot.
    unit = (root / "xentry-wan-firewall.service").read_text()
    assert "ExecStart=/usr/sbin/nft -f /etc/xentry/host-wan.nft" in unit
    assert "WantedBy=multi-user.target" in unit
    # Stopping the unit must NOT remove the rules.
    assert "ExecStop" not in unit.replace(
        "# Deliberately NOT ExecStop=nft delete table", ""
    )


def test_the_hosts_permanent_file_is_idempotent_and_narrow() -> None:
    """Loaded twice, it appended a second copy of every rule.

    proxy-vm-up.sh loads it and then the unit's ExecStart loads it again, and
    nft adds to a table that already exists - so the table doubled, and would
    grow on every reload. The first drop still won, so nothing was insecure;
    it was simply unreadable, which is its own kind of unsafe.

    And the far more important property: this file must never carry
    `flush ruleset`. On the host that would delete libvirt's NAT rules for
    every network and the per-job xentry table with them, mid-job. The VM's
    own firewall.nft may flush, because inside the VM the whole ruleset is
    ours.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "deploy/proxy-vm"
    host = (root / "host-wan.nft").read_text()
    code = "\n".join(
        l for l in host.splitlines() if not l.strip().startswith("#")
    )

    # Clears its own table before defining it, and in that order.
    assert "delete table inet xentry_wan" in code
    assert code.index("table inet xentry_wan\n") < code.index(
        "delete table inet xentry_wan"
    )
    assert code.index("delete table inet xentry_wan") < code.index(
        "table inet xentry_wan {"
    )

    # Never the whole ruleset, on the host.
    assert "flush ruleset" not in code

    # The VM's own file is the opposite case and may flush.
    vm = (root / "firewall.nft").read_text()
    vm_code = "\n".join(l for l in vm.splitlines() if not l.strip().startswith("#"))
    assert "flush ruleset" in vm_code
    assert "xentry_wan" not in vm_code


def test_the_phases_move_into_the_mirror_vm() -> None:
    """The host has no address on a job bridge in stage 2, so it cannot police
    one. The rules go where the address went.

    Both phases are rendered inside the VM from phase.json, and both are
    checked here for the two properties that matter:

      provisioning  both guests may fetch; neither may reach the other
      locked        no guest may fetch; the attacker may reach exactly the
                    target's declared ports

    The locked phase must DROP the mirror ports explicitly rather than simply
    not accepting them: the VM's own xentry_mirror table admits 10.43.0.0/16
    wholesale, so an absent rule would leave a PoC able to fetch during the
    phase that exists to forbid it. That is why the phase table sits at
    priority -10, ahead of it.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    phase = (root / "deploy/proxy-vm/phase.sh").read_text()
    code = "\n".join(l for l in phase.splitlines() if not l.strip().startswith("#"))

    assert "priority -10" in code, "the phase table must precede xentry_mirror"
    assert 'table ${TABLE}\ndelete table ${TABLE}' in code, "must be idempotent"
    # Provisioning: fetch allowed.
    assert 'tcp dport ${MPORTS} accept' in code
    # Locked: no tcp to the VM at all, as an explicit drop.
    assert "meta l4proto tcp drop" in code
    # Locked: one path between the guests, by address and port.
    assert 'ip saddr ${JOBS} ip daddr ${JOBS} accept' in code
    # And nothing else leaves a job subnet - no internet for a guest.
    assert 'ip saddr ${JOBS} drop' in code
    # Scoped by subnet, never by interface name: names depend on PCI slots and
    # have cost two cycles already.
    assert "oifname" not in code and "iifname" not in code
    # A bad phase name is refused rather than rendered.
    assert 'if phase not in ("provisioning", "locked"):' in phase

    # The broker's half.
    runtime = (root / "broker/runtime.py").read_text()
    body = runtime[runtime.index("def set_phase") : runtime.index("def configure_mirror_vm")]
    assert "if not self.proxy_ip:" in body          # off until cutover
    assert "/etc/xentry-mirror/phase.json" in body
    assert "/opt/xentry-mirror/phase.sh" in body
    assert body.count("proxy_vm_unconfigured") == 2


def test_a_job_bridge_has_no_address_on_this_host() -> None:
    """Stage 2's whole point, and the reason the phase rules had to move.

    network_xml with no gateway builds a bridge with no <ip> element at all:
    no address for the host, and therefore no dnsmasq and no route. The guests'
    only neighbour is the proxy VM.
    """
    from broker.libvirt_ops import network_xml

    island = network_xml(
        name="xentry-target", bridge="xentrytgt0",
        target_mac="52:54:00:aa:bb:10", target_ip="", gateway="",
    )
    assert "<ip " not in island and "<dhcp>" not in island
    assert "<forward mode='none'/>" in island
    assert "xentrytgt0" in island

    # The stage-1 shape is untouched: a gateway still produces an address and
    # a dhcp range, because the job network still works that way until the
    # runtime is switched over.
    served = network_xml(
        name="xentry-j", bridge="xentry0",
        target_mac="52:54:00:aa:bb:10", target_ip="10.42.0.10",
    )
    assert "<ip address='10.42.0.1'" in served
    assert "<dhcp>" in served


def test_the_mirror_vm_can_be_given_a_nic_per_job_bridge() -> None:
    """A VM with one interface cannot route between two bridges."""
    from pathlib import Path

    from broker.libvirt_ops import domain_xml

    xml = domain_xml(
        name="xentry-mirror", memory_mb=2048, vcpu=2,
        disk_path=Path("/d.qcow2"), seed_path=Path("/s.iso"),
        network_name="xentry-wan", mac="52:54:00:4d:49:52",
        extra_nics=(("xentry-target", "52:54:00:4d:49:54"),
                    ("xentry-attacker", "52:54:00:4d:49:41")),
    )
    assert xml.count("<interface type='network'>") == 3
    for net, mac in (("xentry-wan", "52:54:00:4d:49:52"),
                     ("xentry-target", "52:54:00:4d:49:54"),
                     ("xentry-attacker", "52:54:00:4d:49:41")):
        assert f"<source network='{net}'/>" in xml
        assert f"<mac address='{mac}'/>" in xml

    # A job VM still gets exactly one, unchanged.
    one = domain_xml(
        name="xentry-target", memory_mb=2048, vcpu=2,
        disk_path=Path("/d.qcow2"), seed_path=Path("/s.iso"),
        network_name="xentry-j", mac="52:54:00:aa:bb:10",
    )
    assert one.count("<interface type='network'>") == 1


def test_the_mirrors_are_unreachable_while_the_poc_runs() -> None:
    """The locked phase is the PoC run. Nothing may be fetched during it.

    This is the property the whole phase model exists for: evidence that a
    PoC worked has to mean the PoC worked, not that it downloaded something
    mid-run. The host enforced it while it had an address on the guests'
    bridge; in stage 2 the proxy VM enforces it, and the rule is stronger
    than the one it replaces - ALL tcp from either guest subnet to the VM is
    dropped, not merely the five mirror ports.

    Both guests, not just the attacker: the target can fetch during
    provisioning and must not be able to afterwards either.
    """
    import json
    import pathlib
    import subprocess
    import tempfile

    root = pathlib.Path(__file__).resolve().parents[1]
    script = (root / "deploy/proxy-vm/phase.sh").read_text()

    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        config = work / "phase.json"
        dry = work / "dry.sh"
        # Render without loading: nft is not present in a test environment and
        # the rules are what is under test, not the kernel's opinion of them.
        dry.write_text(
            script.replace("CONFIG=/etc/xentry-mirror/phase.json", f"CONFIG={config}")
            .replace('if ! out=$(nft -f "$tmp" 2>&1); then', "if false; then")
            .replace("nft list table ${TABLE}", 'cat "$tmp"')
        )
        rendered = {}
        for phase in ("provisioning", "locked"):
            config.write_text(json.dumps({
                "phase": phase,
                "target_ip": "10.43.1.10",
                "attacker_ip": "10.43.2.20",
                "target_ports": [8080],
                "proxy_ports": [80, 8082, 8083, 8084, 8086],
            }))
            done = subprocess.run(
                ["bash", str(dry)], capture_output=True, text=True, check=False
            )
            assert done.returncode == 0, done.stderr
            rendered[phase] = done.stdout

    jobs = "{ 10.43.1.0/24, 10.43.2.0/24 }"

    # During the PoC run: no tcp to the proxy VM from either subnet.
    locked = rendered["locked"]
    assert f"ip saddr {jobs} meta l4proto tcp drop" in locked
    # And no port-specific accept that would undo it.
    assert "8082 } accept" not in locked
    assert "tcp dport { 80," not in locked
    # The two guests may talk to each other without restriction, both ways.
    # It used to be attacker -> target on the declared tcp ports only, which
    # silently decided which CVEs could reproduce: a reverse shell is a NEW
    # connection FROM the target and was dropped, and so was every callback an
    # exploit uses to prove itself. Both machines are sacrificial and already
    # cut off from the host, this VM and the internet by the drop below, so the
    # restriction bought nothing and cost a whole class of PoC.
    assert f"ip saddr {jobs} ip daddr {jobs} accept" in locked
    # Nothing else leaves a guest subnet at all - no internet, no host.
    assert f"ip saddr {jobs} drop" in locked

    # During provisioning the opposite, or no job could install anything.
    provisioning = rendered["provisioning"]
    assert f"ip saddr {jobs} tcp dport {{ 80, 8082, 8083, 8084, 8086 }} accept" in provisioning
    assert "meta l4proto tcp drop" not in provisioning
    # But still no path between the guests.
    assert "10.43.2.20" not in provisioning
    assert f"ip saddr {jobs} drop" in provisioning


def test_dnsmasq_pins_the_macs_the_runtime_actually_uses() -> None:
    """A reservation for a MAC no guest has is a pool address and a missed rule.

    The guests' MACs are fixed constants in runtime.py, which is what makes a
    persistent dnsmasq config possible. An invented pair here would have let
    both guests take dynamic addresses while every rule naming 10.43.1.10
    quietly matched nothing.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    runtime = (root / "broker/runtime.py").read_text()
    conf = (root / "deploy/proxy-vm/dnsmasq-jobs.conf").read_text()

    target = re.search(r'^TARGET_MAC = "([0-9a-f:]+)"', runtime, re.MULTILINE).group(1)
    attacker = re.search(r'^ATTACKER_MAC = "([0-9a-f:]+)"', runtime, re.MULTILINE).group(1)
    # Directives only: the comment explaining the untagged-option bug quotes
    # the broken line, and an assertion on the whole file matches its own
    # explanation. Ninth time today.
    directives = "\n".join(
        l for l in conf.splitlines() if l.strip() and not l.strip().startswith("#")
    )
    assert f"dhcp-host={target},10.43.1.10,target" in directives
    assert f"dhcp-host={attacker},10.43.2.20,attacker" in directives

    # One default route per subnet. A single untagged option would hand the
    # attacker a gateway on the target's subnet.
    assert "dhcp-option=tag:target,3,10.43.1.1" in directives
    assert "dhcp-option=tag:attacker,3,10.43.2.1" in directives
    assert "dhcp-option=tag:,3," not in directives
    assert "set:target" in directives and "set:attacker" in directives


def test_the_runtime_uses_the_island_bridges_when_a_mirror_vm_is_configured() -> None:
    """The cutover, read off the code that performs it.

    Five things have to change together, and a half-cutover is the dangerous
    state: guests on a bridge with a host gateway while the phases are pushed
    to a VM, or guests on island bridges while the host still tries to police
    them. Every branch tests the same attribute, so there is no way to get one
    without the others.
    """
    import pathlib

    runtime = (
        pathlib.Path(__file__).resolve().parents[1] / "broker/runtime.py"
    ).read_text()
    code = "\n".join(
        l for l in runtime.splitlines() if not l.strip().startswith("#")
    )

    # 1. the two persistent networks, named once
    assert 'TARGET_NET = "xentry-target"' in code
    assert 'ATTACKER_NET = "xentry-attacker"' in code

    # 2. a JobNet whose subnets are the island ones, not an allocated octet
    layout = code[code.index("def for_mirror_vm") : code.index("def subnet")]
    assert 'target_ip="10.43.1.10"' in layout
    assert 'attacker_ip="10.43.2.20"' in layout
    assert "octet=0" in layout, "the pool must not be consulted"
    assert 'proxy_url=f"http://{proxy_ip}:{proxy_port}"' in layout

    # 3. a bridge per role, so the VM can route between them
    vm = code[code.index("def _create_vm") : code.index("def _cleanup_vm_files")]
    assert 'network_name = TARGET_NET if role == "target" else ATTACKER_NET' in vm

    # 4. the persistent networks are never destroyed with a job
    cleanup = code[code.index("def _cleanup_network") :]
    cleanup = cleanup[: cleanup.index("def ", 10)]
    assert "if self.proxy_ip:" in cleanup
    assert cleanup.index("if self.proxy_ip:") < cleanup.index("network_destroy")

    # 5. both phases are pushed to the VM instead of applied here
    assert code.count('self.set_phase(') == 2
    locked = code[code.index('self.set_phase(\n                "locked"') :][:600]
    # No proxy_ports in the locked call: phase.sh reads their absence as
    # "drop all tcp from either guest subnet", which is what closes the
    # mirrors to BOTH guests while the PoC runs.
    assert "proxy_ports" not in locked
    # target_ports went with the narrow cross rule: phase.sh reads only the
    # phase and the proxy ports now, so sending the declared ports described a
    # policy that no longer exists.
    # The kwarg, not the word: the call still RETURNS "target_ports" to its
    # caller, which is the broker reporting what it locked.
    assert "target_ports=" not in locked
    # The host has no locked rules of its own any more: that else-branch and
    # its call to locked_rules were deleted with the non-proxy path.
    assert "elif self.apply_nft:" not in code
    assert "locked_rules" not in code


def test_the_guest_urls_point_at_the_mirror_vm() -> None:
    """A guest's mirror used to be its own gateway, which was this host.

    With two island bridges there is no host address to borrow, so every mirror
    is addressed at the VM and reached by routing through it. The ports are
    unchanged, so nothing a guest does changes.

    container_apt_host is the exception and has to be: `docker build` takes no
    flag for an apt proxy, so it gets a host without a port and reaches 80.
    """
    import pathlib

    runtime = (
        pathlib.Path(__file__).resolve().parents[1] / "broker/runtime.py"
    ).read_text()
    code = "\n".join(l for l in runtime.splitlines() if not l.strip().startswith("#"))
    block = code[code.index('base = f"http://{self.proxy_ip}"') :][:1400]

    for name in ("proxy_url", "apt_proxy_url", "attacker_apt_proxy_url",
                 "registry_proxy_url", "oci_mirror_url"):
        assert f"{name} = f\"{{base}}:" in block or f"{name} = (" in block, name
    assert "container_apt_host = self.proxy_ip" in block
    # The registry is still refused without a cutoff: an unpinned index is the
    # one thing it must never serve.
    assert "if self.start_registry_proxy and registry_cutoff" in block


def test_the_bring_up_installs_a_package_before_pushing_its_config() -> None:
    """/etc/dnsmasq.d does not exist until the package does.

    dnsmasq was installed seventy lines AFTER its config was copied, so on a
    VM without it the scp failed with "No such file or directory" - the
    DIRECTORY - set -e killed the bring-up mid-copy, and the VM was left half
    provisioned. The next job then failed with

        /opt/xentry-mirror/phase.sh: No such file or directory

    which is a true statement about a symptom four steps downstream of the
    cause. Ordering the install first removes the class, not just the case.
    """
    import pathlib

    up = (
        pathlib.Path(__file__).resolve().parents[1] / "scripts/proxy-vm-up.sh"
    ).read_text()
    code = "\n".join(l for l in up.splitlines() if not l.strip().startswith("#"))

    # Every package the VM needs is installed in one place.
    assert "for tool in python3 nft dnsmasq; do" in code
    install = code.index("for tool in python3 nft dnsmasq; do")
    # And that place comes before anything is copied in.
    copy = code.index('=== copying the mirrors in')
    assert install < copy, "the config is pushed before the package is installed"
    # Including the config whose directory the package creates.
    conf = code.index("dnsmasq-jobs.conf")
    assert install < conf
    # The directory is made anyway, because a missing one has cost a run.
    assert "/etc/dnsmasq.d" in code


def test_the_host_installs_no_per_job_table_in_stage_two() -> None:
    """A forward chain with policy drop killed the VM's whole network.

    provisioning_rules() still had its wan_bridge and proxy_ip arguments
    threaded through, so it LOOKED converted - but the call was never gated,
    and a job installed

        table inet xentry_mirrorvm
          chain forward { policy drop; ... }

    whose only rules match traffic FROM the guest bridges. Nothing in it
    accepts a packet travelling toward 10.44.0.2, and a drop in any table
    wins - so every reply from the internet died on the way back to the mirror
    VM. A capture showed queries leaving and answers arriving on the uplink
    with nothing reaching the bridge, and the table outlived the job.

    In stage 2 this host holds exactly one table for this: the permanent
    xentry_wan. The phases are the VM's.
    """
    import pathlib

    runtime = (
        pathlib.Path(__file__).resolve().parents[1] / "broker/runtime.py"
    ).read_text()
    code = "\n".join(l for l in runtime.splitlines() if not l.strip().startswith("#"))

    # Both applies used to be gated behind `not self.proxy_ip`. The gated code
    # is gone, so the runtime cannot install a per-job table at all: it has no
    # call to nft.apply and no reference to either rule builder left.
    assert "self.nft.apply(" not in code, "the host installs a per-job table again"
    for builder in ("provisioning_rules", "locked_rules"):
        assert builder not in code, f"{builder} is reachable from the runtime again"
    # The phases go to the VM instead, twice.
    assert code.count("self.set_phase(") == 2


def test_a_registry_is_only_asked_for_when_it_can_be_pinned() -> None:
    """RegistryProxy refuses to exist without a cutoff, and rightly.

    The broker asked for registry_port on every job, cutoff or not, so
    serve.py died with

        TypeError: __init__() missing 1 required keyword-only argument: 'cutoff'

    on every job with no ecosystem target - apache included, which is most of
    them. The host path had always guarded this: `if self.start_registry_proxy
    and registry_cutoff`. The VM path did not.

    An unpinned index would serve whatever is current, and a CVE reproduced
    against a current package is a CVE reproduced against its fix.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    runtime = (root / "broker/runtime.py").read_text()
    serve = (root / "deploy/proxy-vm/serve.py").read_text()
    code = "\n".join(l for l in runtime.splitlines() if not l.strip().startswith("#"))
    vm = "\n".join(l for l in serve.splitlines() if not l.strip().startswith("#"))

    # The port is conditional on the cutoff, and the cutoff travels with it.
    assert '("registry_port", self.registry_port if registry_cutoff else 0)' in code
    assert '("cutoff", registry_cutoff)' in code
    # Falsy entries are dropped, so no cutoff means no registry_port at all.
    assert ") if v}" in code

    # And the VM refuses rather than crashing if one arrives anyway.
    assert 'cutoff = str(config.get("cutoff") or "")' in vm
    assert "if port and not cutoff:" in vm
    assert "cutoff=cutoff" in vm
    # The other mirrors still start: one missing pin must not take them down.
    assert vm.index("if port and not cutoff:") < vm.index("oci_port")


def test_the_state_dict_reads_nothing_that_only_exists_on_the_host() -> None:
    """A KeyError(job_id) reported as harness_error, with no other detail.

    create_network's state dict read

        self.apt_proxies[job_id].archive.check_valid_until

    and self.apt_proxies is populated only when a mirror runs in THIS
    process. With the mirrors in the VM the key is absent, so the job failed
    at step 4 with a detail of nothing but its own id - the least informative
    failure this system has produced.

    check_valid_until is a property of debian-versus-ubuntu and was never the
    proxy's to own. The archive answers for itself, and the state dict now
    touches no per-job proxy registry at all: anything it reads must exist on
    both paths.
    """
    import pathlib
    import re

    runtime = (
        pathlib.Path(__file__).resolve().parents[1] / "broker/runtime.py"
    ).read_text()
    code = "\n".join(l for l in runtime.splitlines() if not l.strip().startswith("#"))

    assert "check_archive(archive_used).check_valid_until" in code
    # The state dict is everything from `state = {` to its closing brace.
    start = code.index("        state = {")
    end = code.index("\n        }", start)
    state = code[start:end]
    # No per-job registry may be indexed there: each is empty in stage 2.
    for registry in ("self.mirrors[", "self.apt_proxies[", "self.attacker_proxies[",
                     "self.oci_mirrors[", "self.registry_proxies[",
                     "self.container_proxies["):
        assert registry not in state, f"the state dict indexes {registry}job_id]"
    # Nothing else in it indexes by job id either.
    assert not re.search(r"self\.\w+\[job_id\]", state), state


def test_the_guest_address_is_known_not_discovered() -> None:
    """libvirt keeps no lease table for a network with no <ip> element.

    An island bridge has no address and no dnsmasq on this host, so
    network_lease_ip() can never answer for it. Every stage-2 job failed with

        no DHCP lease for 52:54:00:00:00:10 on xentry-target

    which would have kept failing with the proxy VM serving leases
    perfectly - the lease exists, in the VM's dnsmasq, where libvirt cannot
    see it.

    It does not need discovering: dnsmasq pins both addresses by MAC from the
    same constants the broker holds. Waiting for ssh on the known address is
    the readiness signal either way.
    """
    import pathlib

    from broker.runtime import ATTACKER_MAC, TARGET_MAC, JobNet

    runtime = (
        pathlib.Path(__file__).resolve().parents[1] / "broker/runtime.py"
    ).read_text()
    code = "\n".join(l for l in runtime.splitlines() if not l.strip().startswith("#"))

    # The shortcut is inside the waiter, so every caller gets it.
    waiter = code[code.index("def _wait_for_ip") : code.index("def _create_vm")]
    assert "if self.proxy_ip:" in waiter
    assert "JobNet.for_mirror_vm" in waiter
    assert waiter.index("if self.proxy_ip:") < waiter.index("network_lease_ip")

    # And the addresses it returns are the ones dnsmasq reserves.
    island = JobNet.for_mirror_vm(8081, "10.44.0.2")
    conf = (
        pathlib.Path(__file__).resolve().parents[1]
        / "deploy/proxy-vm/dnsmasq-jobs.conf"
    ).read_text()
    assert f"dhcp-host={TARGET_MAC},{island.target_ip},target" in conf
    assert f"dhcp-host={ATTACKER_MAC},{island.attacker_ip},attacker" in conf


def test_the_host_has_routes_to_the_guests_through_the_vm() -> None:
    """The broker provisions guests over ssh, and stage 2 cut that path.

    Removing this host's address from the guests' bridges stopped the guests
    reaching the host - intended - and stopped the host reaching the guests,
    which was not. `ip route get 10.43.1.10` resolved via the LAN gateway, so
    the broker's connection left for the internet and create_target waited
    for an ssh that could never arrive.

    The routes go in the same unit as the rules, because they are useless
    without each other and both must outlive a reboot.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    unit = (root / "deploy/proxy-vm/xentry-wan-firewall.service").read_text()
    up = (root / "scripts/proxy-vm-up.sh").read_text()
    directives = "\n".join(
        l for l in unit.splitlines() if not l.strip().startswith("#")
    )

    for subnet in ("10.43.1.0/24", "10.43.2.0/24"):
        assert f"ExecStartPost=/sbin/ip route replace {subnet} via 10.44.0.2" in directives
        assert 'ip route replace "$subnet" via "$PROXY_IP"' in up or subnet in up

    # The bring-up proves the route before trusting it: the VM's own job-side
    # addresses must answer, or no guest on those bridges will.
    code = "\n".join(l for l in up.splitlines() if not l.strip().startswith("#"))
    assert "for addr in 10.43.1.1 10.43.2.1; do" in code
    assert "does not answer - the broker will not reach a guest" in up

    # And the guest-to-host direction is still closed, in all three places.
    phase = (root / "deploy/proxy-vm/phase.sh").read_text()
    egress = (root / "deploy/proxy-vm/firewall.nft").read_text()
    host = (root / "deploy/proxy-vm/host-wan.nft").read_text()
    assert "ip saddr ${JOBS} drop" in phase
    assert "ip daddr 10.44.0.1 drop" in egress
    assert 'iifname "xentrywan0" drop' in host


def test_guest_ssh_is_tunnelled_through_the_mirror_vm() -> None:
    """Every guest command rides through the VM, so the host needs no route.

    proxy_command rather than asyncssh's `tunnel=`, and the choice is forced
    by asyncssh 2.24's own code: a STRING tunnel is built with only
    `passphrase` and `config`, never `client_keys`, so it would search
    ~/.ssh/id_* and never find the proxy key; a tunnel OBJECT is only closed
    by asyncssh in the string case, so each command would leak a connection.

    Read from the environment inside SSHTransport because runtime.py builds
    one in seven places, none of which should have to know about the VM.
    """
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1] / "broker/exec_ops.py").read_text()
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))

    assert 'JUMP_HOST = "10.44.0.2"' in code
    assert 'JUMP_KEY = "/etc/xentry/proxy-vm.key"' in code
    assert 'os.environ.get("XENTRY_SSH_JUMP", JUMP_HOST)' in code
    assert "proxy_command=jump if self.jump else ()" in code
    # NOT %h:%p. asyncssh execs the token list as given and substitutes
    # nothing - grep the package for %h and it is absent - so a placeholder
    # reaches ssh literally, which is a bad forwarding specification. ssh then
    # exits instantly, asyncssh reports "Connection lost", and the usage error
    # goes to stderr rather than the -E log, so the log stays empty and the
    # tunnel looks as though it never ran.
    assert "%h" not in code and "%p" not in code
    assert "-W {self.host}:{self.port}" in code
    assert "root@{self.jump}" in code
    assert "ssh -i {JUMP_KEY}" in code
    # And the tunnel must record its own reason, because a proxy command
    # turns every inner failure into an indistinguishable "Connection lost".
    assert "-E /var/lib/xentry/jump.log" in code
    # tunnel= must not be used, for the two reasons above.
    assert "tunnel=" not in code


def test_dnsmasq_serves_dhcp_on_the_job_bridges() -> None:
    """`interface=lo` plus `except-interface=lo` left DHCP on no interface.

    dnsmasq reported itself active, answered nothing, and the guest booted
    with no address - which reached the broker as
    [Errno 113] Connect call failed ('10.43.1.10', 22), EHOSTUNREACH, because
    the VM ARPed for an address nobody held.

    With no interface directives, dnsmasq offers DHCP wherever an interface's
    own address falls inside a dhcp-range: ens3 and ens4, never the wan NIC,
    which has no range. It also needs no interface NAMES.
    """
    import pathlib

    conf = (
        pathlib.Path(__file__).resolve().parents[1]
        / "deploy/proxy-vm/dnsmasq-jobs.conf"
    ).read_text()
    live = [l.strip() for l in conf.splitlines()
            if l.strip() and not l.strip().startswith("#")]

    for directive in live:
        assert not directive.startswith("interface="), directive
        assert not directive.startswith("listen-address="), directive
    assert "bind-dynamic" in live

    # lo is NOT excluded, deliberately: dnsmasq on 127.0.0.1:53 is the one
    # resolver in the VM with upstreams we chose, and resolv.conf points at
    # it. The sockets proved it never clashed with systemd-resolved, which
    # holds 127.0.0.53 - a different address.
    assert "except-interface=lo" not in live
    assert "no-resolv" in live
    assert any(d.startswith("server=") for d in live)
    # The ranges are what enable DHCP, so they must cover both gateways.
    assert any(d.startswith("dhcp-range=set:target,10.43.1.") for d in live)
    assert any(d.startswith("dhcp-range=set:attacker,10.43.2.") for d in live)
    # And the wan subnet must have no range at all.
    assert not any("10.44.0." in d for d in live if d.startswith("dhcp-range"))


def test_the_vm_ssh_is_reachable_only_from_the_host() -> None:
    """Port 22 in the VM is the broker's jumphost, so it is whitelisted.

    It was `tcp dport 22 accept` with no source, under a blanket
    `ip saddr 10.43.0.0/16 accept` that reached every other port as well. A
    guest could therefore reach the jumphost and ask it to forward anywhere
    the VM can reach.

    Now only 10.44.0.1 - this host on xentrywan0 - is accepted at all, and
    the guests are limited to DHCP, DNS and the mirror range.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    nft = (root / "deploy/proxy-vm/firewall.nft").read_text()
    rules = [l.strip() for l in nft.splitlines()
             if l.strip() and not l.strip().startswith("#")]
    inp = rules[rules.index("chain input {"):]
    inp = inp[: inp.index("}")]

    assert "policy drop;" in " ".join(inp)
    assert "ip saddr 10.44.0.1 accept" in inp
    # No unconditional ssh, and no blanket acceptance of the job subnets.
    assert "tcp dport 22 accept" not in inp
    assert "ip saddr 10.43.0.0/16 accept" not in inp
    assert not any(re.fullmatch(r"ip saddr 10\.43\.[0-9./]+ accept", r) for r in inp)

    # What the guests may reach: DHCP, DNS, the mirrors, and a ping.
    assert any("udp dport { 53, 67 } accept" in r for r in inp)
    assert any("tcp dport 8081-8086 accept" in r for r in inp)
    # And 22 is outside whatever that range actually says, which is the point.
    rule = next(r for r in inp if "tcp dport" in r and "-" in r)
    low, high = (int(x) for x in rule.split("dport ")[1].split(" ")[0].split("-"))
    assert not low <= 22 <= high, rule

    # And the phase table still decides whether the mirrors answer right now.
    phase = (root / "deploy/proxy-vm/phase.sh").read_text()
    assert "ip saddr ${JOBS} meta l4proto tcp drop" in phase


def test_the_island_bridges_forward_without_delay() -> None:
    """A new port must forward at once, or a booting guest is talking to a wall.

    network_xml renders delay='0', but both bridges reported
    forward_delay=200 - two seconds LISTENING plus two LEARNING - because the
    networks had been defined by an earlier version of the XML and the
    bring-up printed "already defined" rather than comparing.

    A guest sends its first DHCP DISCOVER inside that window, and a probe
    attached to the bridge gets nothing for four seconds, which is how a
    working whitelist looked like a broken one.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    up = (root / "scripts/proxy-vm-up.sh").read_text()
    code = "\n".join(l for l in up.splitlines() if not l.strip().startswith("#"))
    lib = (root / "broker/libvirt_ops.py").read_text()

    assert "stp='on' delay='0'" in lib
    # The stale definition is detected and replaced, not reported as fine.
    # Asserted on the check, not on the grep flag it uses: this said grep -q
    # and so broke when that -q was fixed to -c, which under pipefail is a
    # correctness fix (grep -q closes the pipe and the writer takes SIGPIPE).
    # A test that pins an implementation detail fails the fixes it should pass.
    assert "virsh net-dumpxml" in code
    assert "delay='0'" in code
    assert "virsh net-undefine" in code
    # And the live bridge is corrected without waiting for a redefinition.
    assert 'ip link set "$2" type bridge forward_delay 0' in code


def test_the_filter_lets_dhcp_through_in_both_directions() -> None:
    """No version of this filter has ever allowed DHCP, and that was the bug.

    A DISCOVER is saddr 0.0.0.0 -> daddr 255.255.255.255, udp 68 -> 67. It has
    no source address yet, so it matched neither `ip saddr 10.43.0.0/16
    accept` nor the narrower whitelist that replaced it, and the input chain's
    policy drop ate it. A capture on the VM's ens3 showed seven DISCOVERs from
    52:54:00:00:00:10 arriving while dnsmasq sat on 0.0.0.0:67 with both
    ranges loaded.

    The reply was dropped too: 10.43.1.10 is inside the 10.0.0.0/8 private
    drop in the output chain. That never surfaced as a mirror failure because
    guest-initiated TCP is covered by `ct state established`; only traffic the
    VM itself starts had no state to match.
    """
    import pathlib

    nft = (
        pathlib.Path(__file__).resolve().parents[1] / "deploy/proxy-vm/firewall.nft"
    ).read_text()
    rules = [l.strip() for l in nft.splitlines()
             if l.strip() and not l.strip().startswith("#")]
    inp = rules[rules.index("chain input {"):]
    inp = inp[: inp.index("}")]
    out = rules[rules.index("chain output {"):]
    out = out[: out.index("}")]

    # In: matched by port pair, never by source, since there is no source yet.
    assert "udp sport 68 udp dport 67 accept" in inp

    # Out: the job subnets are accepted BEFORE the private-range drop, or the
    # reply dies on the way out.
    job = next(i for i, r in enumerate(out)
               if r.startswith("ip daddr { 10.43.1.0/24, 10.43.2.0/24 } accept"))
    bcast = next(i for i, r in enumerate(out) if r == "ip daddr 255.255.255.255 accept")
    private = next(i for i, r in enumerate(out) if "10.0.0.0/8" in r and "drop" in r)
    assert job < private, out
    assert bcast < private, out

    # And the guests still cannot be reached past their own subnets.
    assert any("ip daddr 10.44.0.1 drop" == r for r in out)


def test_the_vm_resolves_through_a_resolver_we_control() -> None:
    """resolv.conf must be a real file, not a symlink resolved rewrites.

    On an Ubuntu base /etc/resolv.conf is a symlink into
    /run/systemd/resolve/, so writing to it wrote into resolved's own stub.
    resolved put 127.0.0.53 back and took its real upstream per-link from
    DHCP on the wan NIC, which libvirt answers with 10.44.0.1 - the host, the
    single address the VM's egress filter exists to drop. The mirrors then
    failed with [Errno -3] Temporary failure in name resolution while every
    check in the bring-up still passed.

    dnsmasq goes first because it runs in the VM with explicit public
    upstreams and is the resolver the guests already use. The public servers
    follow it so that a dnsmasq which is not up yet refuses instantly rather
    than hanging.
    """
    import pathlib

    up = (
        pathlib.Path(__file__).resolve().parents[1] / "scripts/proxy-vm-up.sh"
    ).read_text()
    code = "\n".join(l for l in up.splitlines() if not l.strip().startswith("#"))

    assert "rm -f /etc/resolv.conf" in code
    assert "'nameserver 127.0.0.1' 'nameserver 1.1.1.1' 'nameserver 9.9.9.9'" in code
    assert "systemctl disable --now systemd-resolved" in code

    # The second check must come AFTER dnsmasq is installed: the first one
    # could not see a break that installing dnsmasq caused.
    installed = code.index("for tool in python3 nft dnsmasq; do")
    rechecked = code.index("resolution STILL works")
    assert installed < rechecked, "the recheck must follow the dnsmasq install"

    # And the resolver is fixed before anything uses apt.
    fixed = code.index("rm -f /etc/resolv.conf")
    assert fixed < installed


def test_the_attacker_mirror_is_ubuntu_and_unpinned() -> None:
    """The attacker is a toolbox, not evidence, so it takes the live archive.

    serve.py handed the target's archive and serial to all three apt proxies,
    so an Ubuntu noble attacker was given a Debian snapshot and asked for
    /ubuntu/dists/noble/InRelease:

        403 refused path for debian: /ubuntu/dists/noble/InRelease
        this serial predates -updates/-security: release pocket only

    The host has always done it differently - runtime.py passes serial=None
    and archive="ubuntu" for the attacker port, while the target and the
    container runtime stay pinned to the snapshot the CVE's dates demand.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    serve = (root / "deploy/proxy-vm/serve.py").read_text()
    code = "\n".join(l for l in serve.splitlines() if not l.strip().startswith("#"))

    # The attacker is the only unpinned one.
    assert '("target", "apt_port", True)' in code
    assert '("container runtime", "container_apt_port", True)' in code
    assert '("attacker", "attacker_apt_port", False)' in code
    assert "serial=str(serial) if pinned else None" in code
    assert 'archive=archive if pinned else "ubuntu"' in code

    # And the broker still refuses to serve a target without a pinned serial,
    # which is the guarantee this must not weaken.
    assert "refusing to serve: job.json names no serial or no archive" in serve

    # There is no host-side apt proxy left to drift from: the block that built
    # one was deleted with the non-proxy path, so serve.py's choice above is
    # the only one that exists.
    runtime = (root / "broker/runtime.py").read_text()
    assert "port=self.attacker_apt_port" not in runtime
    assert "AptSnapshotProxy(" not in runtime

def test_the_lock_does_not_cut_the_brokers_control_channel() -> None:
    """copy_poc runs after lock_network, and the lock dropped its ssh.

    Every guest command is tunnelled through the VM now, so when the locked
    phase dropped all tcp from the job subnets it also dropped the replies
    from the guest's own sshd to a connection the VM had opened:

        guest SSH did not become ready: Login timeout expired

    The forward chain has carried an established exemption from the start.
    The input chain never did, because before the mirrors moved into a VM the
    control channel did not pass through one.

    The exemption is narrow on purpose: sport 22 and established only, so it
    admits a reply on a flow the VM initiated and nothing a guest can start.
    """
    import pathlib

    phase = (
        pathlib.Path(__file__).resolve().parents[1] / "deploy/proxy-vm/phase.sh"
    ).read_text()
    code = "\n".join(l for l in phase.splitlines() if not l.strip().startswith("#"))

    exempt = "ip saddr ${JOBS} tcp sport 22 ct state established,related accept"
    assert exempt in code

    # It must precede the blanket tcp drop, or it accomplishes nothing: the
    # drop is injected as ${rules} after the chain's fixed lines.
    inp = code[code.index("chain input {"):code.index("chain forward {")]
    assert exempt in inp, inp
    assert "${rules}" in inp
    assert inp.index(exempt) < inp.index("${rules}")

    # And the lock still cuts what it is for: new tcp from a guest.
    assert "ip saddr ${JOBS} meta l4proto tcp drop" in code
    # Only port 22 is exempt - never a mirror port.
    assert "sport 8081" not in code and "sport { 53" not in code


def test_the_island_net_is_not_rebuilt_from_a_stored_octet() -> None:
    """_net must not reconstruct the old scheme on the mirror-VM path.

    for_mirror_vm records octet=0, so a caller rebuilding a net from stored
    state got for_octet(0, ...) - 10.42.0.10 and 10.42.0.20. lock_network
    then wrote a cross rule for a pair of addresses no guest has:

        ip saddr 10.42.0.20 ip daddr 10.42.0.10 tcp dport 80 accept

    while the guests were 10.43.2.20 and 10.43.1.10, so the PoC's traffic
    fell through to the job-subnet drop, its curl failed silently, and the
    step reported only its own invoking line - twice, after eighteen steps.

    Job creation already chose correctly; _net did not, and lock_network goes
    through _net. The split bridges are what exposed it: while both guests
    shared one bridge their traffic was switched at layer 2 and this rule was
    never exercised.
    """
    import pathlib

    src = (
        pathlib.Path(__file__).resolve().parents[1] / "broker/runtime.py"
    ).read_text()
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))

    body = code[code.index("def _net(self, job_id: str) -> JobNet:") :]
    body = body[: body.index("\n    def ", 1)]
    # The island check comes FIRST, before anything reads the stored octet.
    assert "if self.proxy_ip:" in body
    assert "return JobNet.for_mirror_vm(self.proxy_port, self.proxy_ip)" in body
    assert body.index("if self.proxy_ip:") < body.index('state.get("octet")')

    # The phase rules are fed from a net, which is what this fixes.
    assert "target_ip=net.target_ip" in code
    assert "attacker_ip=net.attacker_ip" in code


def test_the_poc_step_says_whether_the_target_was_reachable() -> None:
    """A PoC that cannot connect prints nothing, so the step must say so.

    exec passes the PoC's streams straight through, so when blasty's
    exploit.sh failed to reach the target it printed nothing and the step's
    entire detail was its own invoking line. Twice.
    """
    import hashlib
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    script = root / "targets/common/run-poc-generic.sh"
    text = script.read_text()
    code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))

    assert 'exec 3<>/dev/tcp/$target_ip/$port' in code
    assert "UNREACHABLE:" in code
    # Before the invocation, or it tells us nothing we did not already have.
    assert code.index("UNREACHABLE:") < code.index("invoking:")
    # Bounded, and with no dependency on curl or nc being present.
    assert "timeout 3 bash -c" in code

    # And the manifest digest must match, or the broker refuses the step.
    manifest = (root / "targets/steps.yaml").read_text()
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    pairs = {
        rel: sha
        for rel, sha in re.findall(
            r"script:\s*(\S+)\s*\n\s*sha256:\s*([0-9a-f]{64})", manifest
        )
    }
    assert pairs.get("common/run-poc-generic.sh") == digest


def test_the_registry_advertises_an_address_a_guest_can_reach() -> None:
    """RegistryProxy puts its BIND ADDRESS into the index it serves.

    url is f"http://{self.bind}:{self.port}" and the pypi and npm filters
    rewrite every file URL through it, so bind=0.0.0.0 told pip to fetch
    wheels from http://0.0.0.0:8083/..., which Linux resolves to the guest's
    own loopback:

        HTTPConnectionPool(host='0.0.0.0', port=8083) ... Connection refused

    Job d4925cca2cea died there, installing the attacker's toolbox, after nine
    steps had passed. The index request itself had worked, so routing and
    filtering were never implicated - the bytes the mirror served named an
    address no guest can reach.

    apt is unaffected because sources.list carries the base and index paths
    are relative, which is why apt worked in that same job.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    serve = (root / "deploy/proxy-vm/serve.py").read_text()
    code = "\n".join(l for l in serve.splitlines() if not l.strip().startswith("#"))

    assert 'ADVERTISED = "10.44.0.2"' in code
    # The registry gets the routable address; the others keep the wildcard,
    # because nothing they serve embeds it.
    registry = code[code.index("RegistryProxy(") :]
    registry = registry[: registry.index(")")]
    assert "bind=ADVERTISED" in registry
    assert "bind=BIND" not in registry
    # And it must match the address the broker tells guests to use.
    runtime = (root / "broker/runtime.py").read_text()
    assert 'PROXY_VM_IP = "10.44.0.2"' in runtime

    # The property this depends on, so a refactor there fails here too.
    proxy = (root / "broker/registryproxy.py").read_text()
    assert 'return f"http://{self.bind}:{self.port}"' in proxy


def test_the_two_exec_paths_cannot_be_mixed() -> None:
    """This is the line the whole harness mode's containment rests on.

    `exec` refuses a script whose bytes do not match the digest in
    steps.yaml. Harness mode adds a second comparison - against the digest the
    runner recorded for THIS job's generated script - and a second branch on
    the most security-relevant check in the broker is how a gate quietly stops
    being one.

    Three properties, each of which is "the obvious refactor" away from being
    broken:

    1. The reserved id is not in steps.yaml, so the generated script can never
       resolve as a manifest step.
    2. script_sha256 with a manifest step is REFUSED, not ignored. Dropping it
       silently would let a caller believe a digest had been checked.
    3. The script path is derived from the vm's job, never passed, so job A's
       script cannot run against job B's VM by construction.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    src = (root / "broker/runtime.py").read_text()
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))

    # 1. reserved, and absent from the manifest.
    assert 'GENERATED_STEP = "provision-generated"' in code
    manifest = pathlib.Path("/opt/xentry-broker/targets/steps.yaml")
    if manifest.exists():
        assert "provision-generated" not in manifest.read_text()

    # 2. the mixing refusal, and that it precedes the manifest lookup.
    body = code[code.index("def exec_step(") :]
    body = body[: body.index("\n    def ", 1)]
    assert "if step_id == GENERATED_STEP:" in body
    assert "if script_sha256:" in body
    assert body.index("if script_sha256:") < body.index("self._steps().get(step_id)")

    # 3. the path is derived from the state, with no path parameter anywhere.
    gen = code[code.index("def exec_generated(") :]
    gen = gen[: gen.index("\n    def ", 1)]
    assert 'self.jobs_root / str(state["job_id"]) / GENERATED_SCRIPT' in gen
    assert "path" not in re.sub(r"\s+", "", gen.split(")")[0]), "no path parameter"
    # And the digest is required and checked before anything runs.
    assert "SHA256_RE.fullmatch" in gen
    assert gen.index("_sha256_file(script) != script_sha256") < gen.index("ssh.run(")
    # The generated script is still target-only by a check, because `exec`
    # addresses a VM for every step and cannot name a role in its verb.
    assert 'state.get("role") != "target"' in gen


def test_free_exec_is_a_separate_door_and_exec_keeps_its_guard() -> None:
    """Adding a verb must not widen the one that already existed.

    `exec`'s dispatch refuses {argv, command, shell, user} in a step's params
    with "raw command rejected". That guard is why a model could never smuggle
    a command through a registered step, and it stays exactly as it was - the
    new capability is a different verb, declared in VERB_PARAMS, not a relaxed
    parameter set on the old one.

    The rename to restricted_exec was rejected for the audit trail: every
    broker_calls row ever written says `exec` and means the restricted one.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    main = (root / "broker/main.py").read_text()
    runtime = (root / "broker/runtime.py").read_text()

    # One verb per role, and NEITHER takes a vm_id: the role is in the name and
    # the machine is resolved from the job, so there is no role check to forget
    # in a refactor. Root only - no user parameter to choose an identity with.
    for verb in ("free_exec_target", "free_exec_attacker"):
        assert f'"{verb}": frozenset({{"job_id", "command", "timeout_s"}})' in main, verb
        assert f'"{verb}",' in main  # in RUNTIME_VERBS
    assert '"user"' not in main.split("free_exec_target")[1][:200]

    # exec's own guard is untouched.
    assert '{"argv", "command", "shell", "user"} & set(inner)' in runtime
    assert "raw command rejected" in runtime
    # And the old verb still carries its name.
    assert '"restricted_exec"' not in main

    # A free command is bounded in time and in captured output, with the
    # digests taken over the FULL output so a truncated field is attributable.
    assert "FREE_EXEC_MAX_S" in runtime and "FREE_EXEC_MAX_LOG" in runtime
    free = runtime[runtime.index("def free_exec(") :]
    free = free[: free.index("\n    def ", 1)]
    assert "hashlib.sha256(result.stdout.encode())" in free
    # The machine comes from the job and the role, never from a parameter.
    assert 'self.jobs_root / job_id / role / "state.json"' in free
    # THE SIGNATURE, not the body: the docstring explains why there is no
    # vm_id, and a substring search over the whole method matched that
    # explanation. Eleventh time in this codebase that a check has matched its
    # own prose - comments are stripped for the same reason elsewhere, and a
    # docstring is not a comment.
    signature = free.split(")")[0]
    assert "vm_id" not in signature, signature


def _depends_on_retired(line: str) -> bool:
    """Does this line NEED the retired tree, as opposed to cleaning it up?

    uninstall.sh removes /opt/xentry-broker.retired.* - leftovers the collapse
    created, which it is right to delete. That substring contains the old path
    but is a different directory, so matching the bare string flagged the
    uninstaller for doing its job. Only the tree itself counts: the path
    followed by a slash, a quote, or the end of the token.
    """
    import re

    return bool(re.search(r"/opt/xentry-broker(?![.\w])", line))

def test_nothing_still_points_at_the_retired_broker_tree() -> None:
    """The duplicate tree was retired, and one script still needed it.

    scripts/proxy-vm-up.sh had BROKER=/opt/xentry-broker as a plain
    assignment - not overridable - and three inlined Python blocks doing
    sys.path.insert(0, "/opt/xentry-broker"). Collapsing the two trees deleted
    that directory, so the proxy VM's bring-up could no longer render a
    network or a domain XML. Nothing caught it: it was found while rewriting
    the README against the new layout, which is luck rather than process.

    A reference inside a comment is allowed - the history is worth keeping -
    so this reads code only.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    # By extension, a profile named local-libvirt-qemu slipped past: deploy/
    # holds units and AppArmor profiles as well as scripts, so read all of it.
    candidates = [p for p in root.glob("scripts/*.sh")]
    candidates += [p for p in root.glob("*.sh")]
    candidates += [p for p in (root / "deploy").rglob("*") if p.is_file()]
    for pattern in (None,):
        for path in candidates:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                if _depends_on_retired(stripped):
                    offenders.append(f"{path.relative_to(root)}:{number}")
    for path in (root / "broker").rglob("*.py"):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if _depends_on_retired(stripped):
                offenders.append(f"{path.relative_to(root)}:{number}")
    assert not offenders, "still reference the retired tree: " + ", ".join(offenders)


def test_the_bring_up_reads_its_payload_from_the_tree() -> None:
    """An installed script must not read files out of a developer's home.

    SRC was hardcoded to /home/seclab/xentry-work/env, so the copy installed
    at /opt/xentry/scripts fetched the VM's files from one person's work tree.
    On any other machine - and on the from-zero clone this project is about to
    be tested with - step 11 fails at its first scp.
    """
    import pathlib

    text = (
        pathlib.Path(__file__).resolve().parents[1] / "scripts/proxy-vm-up.sh"
    ).read_text()
    code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
    assert 'SRC="${SRC:-/opt/xentry}"' in code
    assert "/home/seclab" not in code, "a developer's home is still baked in"


def test_no_shell_script_ends_a_pipeline_in_grep_q_under_pipefail() -> None:
    """`cmd | grep -q needle` is a lie under `set -o pipefail`.

    grep -q exits at its first match and closes the pipe. The writer then dies
    of SIGPIPE, and pipefail reports the pipeline as 141 - failure - for a
    pipeline that FOUND what it was looking for. It is invisible while the
    writer's output fits the 64KB pipe buffer, so it passes on small inputs and
    starts failing as data grows.

    Found the hard way: a verifier claimed `BROKER does not point at the tree`
    about a file that said exactly that, because the stripped script was 633
    lines. The same pattern was then found in nine places, two of which mattered
    - `dpkg -l | grep -q "^i"` reported "the debs did not install" after a
    successful dpkg -i (dpkg -l is 212KB), and `zcat changelog | grep -q CVE`
    would report a package does not name its CVE when it does, defeating the
    one guard that keeps "did not reproduce" distinct from "already patched".

    `grep -c` reads to the end, so there is no early close and no signal.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    paths = sorted(
        set(root.glob("*.sh"))
        | set(root.glob("scripts/*.sh"))
        | set(root.glob("deploy/**/*.sh"))
        | set(root.glob("targets/**/*.sh"))
    )
    offenders: list[str] = []
    for path in paths:
        text = path.read_text()
        if "pipefail" not in text:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r"\|\s*grep\s+-[a-zA-Z]*q", stripped):
                offenders.append(f"{path.relative_to(root)}:{number}")
    assert not offenders, (
        "pipeline ends in grep -q under pipefail (use grep -c and compare): "
        + ", ".join(offenders)
    )


def test_install_does_not_treat_the_mirror_vm_as_optional() -> None:
    """The broker addresses the VM whether or not it was built.

    broker/main.py resolves `proxy_ip` as `os.environ.get("XENTRY_PROXY_IP") or
    PROXY_VM_IP`, and PROXY_VM_IP is the constant "10.44.0.2". It is therefore
    never empty: every `if self.proxy_ip:` branch in the runtime is taken and
    the `if not self.proxy_ip:` guards cannot be reached from the deployed
    configuration. ADR 0002 removed the in-process mirrors and left no value
    that brings them back.

    So an install that skips the VM produces a broker pointed at a machine that
    does not exist, and every job fails at provision for want of a package
    mirror. The step was gated on INSTALL_PROXY_VM=1, default off, which made
    that the DEFAULT outcome. Building it is the default now; SKIP_PROXY_VM=1
    is the opt-out.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    install = (root / "install.sh").read_text()
    code = "\n".join(l for l in install.splitlines() if not l.strip().startswith("#"))

    assert 'step "the proxy VM"' in code, "step 11 is labelled optional again"
    # No gate at all, in either direction. A flag that produces a deployment
    # which cannot run a job is not a choice worth offering: it only moves the
    # failure to the first job, where a missing machine looks like a
    # provisioning bug.
    assert "INSTALL_PROXY_VM" not in code, "the opt-in gate is back"
    assert "SKIP_PROXY_VM" not in code, "an opt-out was added"

    # And the reason it is mandatory must still hold in the broker.
    main = (root / "broker/main.py").read_text()
    assert 'os.environ.get("XENTRY_PROXY_IP") or PROXY_VM_IP' in main
    runtime = (root / "broker/runtime.py").read_text()
    assert 'PROXY_VM_IP = "10.44.0.2"' in runtime


def test_the_host_no_longer_runs_any_package_service() -> None:
    """Six tests were deleted with the code they covered. This is what they said.

    They asserted that the broker started an ArtifactMirror, an
    AptSnapshotProxy, an OciMirror and a RegistryProxy on this host, bound to
    each job network's gateway, and installed a per-job nftables table to
    police them. All four were gated behind `not self.proxy_ip`, and proxy_ip
    defaults to the constant 10.44.0.2, so none of it could run - it was a
    second implementation of the same job kept alive only by its tests.

    ADR 0002 moved those services into the proxy VM. deploy/proxy-vm/serve.py
    runs the three proxies there, phase.sh holds the firewall, and the host
    offers a guest nothing at all. What is asserted here is the absence: a
    second path that cannot run is worse than no second path, because a reader
    cannot tell which one a job used.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    runtime = (root / "broker/runtime.py").read_text()
    code = "\n".join(l for l in runtime.splitlines() if not l.strip().startswith("#"))

    for gone in ("ArtifactMirror", "AptSnapshotProxy(", "OciMirror(",
                 "RegistryProxy(", "provisioning_rules", "locked_rules",
                 "self.nft.apply("):
        assert gone not in code, f"the host-side package path is back: {gone}"

    # And the three that DO still exist run in the VM, not here.
    serve = (root / "deploy/proxy-vm/serve.py").read_text()
    for lives in ("AptSnapshotProxy", "OciMirror", "RegistryProxy"):
        assert lives in serve, f"{lives} should still run inside the VM"


def test_the_artifact_mirror_module_is_gone() -> None:
    """broker/mirror.py is deleted, and that leaves a KNOWN GAP.

    I removed it as dead code and described it as a second implementation of
    something the proxy VM already did. The first half was right - its only
    caller was behind `start_mirror and not self.proxy_ip`, and proxy_ip
    defaults to 10.44.0.2, so it could never run. The second half was wrong.

    It was not a duplicate. It was the ORIGINAL of a service that never moved
    into the VM. deploy/proxy-vm/serve.py binds five ports - three apt, one
    registry, one OCI - and nothing on 8081, which is where
    targets/*/setup.sh fetches pinned software from:

        curl -fsS "$proxy_url/artifacts/$artifact_id" -o "$tarball"

    So every typed target (php2shell, gitlab, dirtyfrag) fails at provision
    with `curl: (7) Failed to connect to 10.44.0.2 port 8081`, and has done
    since the ADR 0002 cutover - not since this deletion. Generic targets are
    unaffected: they fetch from the apt proxy on 8082, which is why
    CVE-2021-41773 and CVE-2025-32463 still reproduce.

    The decision on record is that generic is the path forward, so this is
    documented rather than rebuilt. See docs/security/permission_changes.md's
    sibling note in docs/designs/proxy-vm-isolation.md. If a typed target is
    ever needed again, the module is at `git show 25a8997~1:broker/mirror.py`
    and the work is a sixth service in serve.py plus a per-job copy of the
    approved artifacts into the VM.

    This test asserts the module stays gone, so nobody reintroduces the
    host-side version by accident - the fix belongs in the VM.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    assert not (root / "broker/mirror.py").exists()
    assert not (root / "tests/test_mirror.py").exists()
    # The three that DO serve packages live in the VM and are copied there.
    up = (root / "scripts/proxy-vm-up.sh").read_text()
    assert "for f in aptproxy ociproxy registryproxy; do" in up


def test_the_target_may_open_a_connection_back_to_the_attacker() -> None:
    """A reverse shell is a NEW connection from the target, and it was dropped.

    The locked phase permitted exactly one flow between the guests: attacker to
    target, tcp, on the ports the target declared. `ct state
    established,related` then covered the replies on that flow - but only that
    flow. Anything the target initiated was caught by the drop:

      * a reverse shell, which is the usual payload for an RCE
      * Log4Shell's JNDI fetch, and every other callback an exploit uses to
        prove it ran
      * an XXE or SSRF probe

    The PoC failed and the job reported that the exploit did not reproduce,
    which is a verdict about the CVE for a packet the firewall ate.

    Both guests are sacrificial, on island bridges with no host address, and
    the drop below still cuts them off from this VM, the host and the internet.
    The only thing the old rule restricted was the one conversation the job
    exists to have.
    """
    import pathlib

    script = (
        pathlib.Path(__file__).resolve().parents[1] / "deploy/proxy-vm/phase.sh"
    ).read_text()
    code = "\n".join(l for l in script.splitlines() if not l.strip().startswith("#"))

    # Symmetric: the match is subnet-to-subnet, so direction does not enter.
    assert 'cross="    ip saddr ${JOBS} ip daddr ${JOBS} accept"' in code
    # Not conditional on the phase, and not on the declared ports.
    assert "tcp dport ${TPORTS}" not in code
    assert '${ATTACKER} ip daddr ${TARGET}' not in code
    # And the isolation that matters is untouched.
    assert "ip saddr ${JOBS} drop" in code
    assert "ip saddr ${JOBS} meta l4proto tcp drop" in code


def test_the_bring_up_does_not_need_an_index_to_exist() -> None:
    """Step 11 died on a fresh host with a sqlite traceback.

    proxy-vm-up.sh opens /var/lib/xentry/xentry.db read-only to refuse while a
    job is running. The app creates that file and applies its migrations on
    first start, so on a fresh install - or after a reset that cleared the
    state - it is not there yet. sqlite3 raised, the command substitution
    failed, and `set -euo pipefail` ended the step with

        sqlite3.OperationalError: unable to open database file

    which reads as a broken bring-up rather than "there is no job to wait for".
    No database, and no jobs table, both mean nothing can be in flight.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    up = (root / "scripts/proxy-vm-up.sh").read_text()
    block = up[up.index("inflight=$("):up.index("job(s) running")]
    assert "except sqlite3.Error:" in block, "a missing index still raises"
    assert "print(0)" in block

    # The read-only tool is what you reach for on exactly that host, so it
    # must say so once rather than traceback from three separate connects.
    read = (root / "scripts/xentry-read.sh").read_text()
    assert "need_db()" in read
    code = "\n".join(l for l in read.splitlines() if not l.strip().startswith("#"))
    assert code.count("need_db") >= 6, "not every index-reading subcommand guards"


def test_the_base_image_the_bring_up_asks_for_is_one_that_gets_built() -> None:
    """Step 11 asked for a file nothing produces.

    build-images.py writes a base image under its ARTIFACT name -
    f"{spec['base_artifact']}.img" - because three releases have three
    different bases and one shared filename made each build overwrite the
    last. install.sh still overrode BASE with ubuntu-24.04-base.img, a name
    from before that change, so the bring-up stopped with

        /var/lib/xentry/images/ubuntu-24.04-base.img is missing

    on a host where every image was present and correct. The name has to be an
    artifact in the catalog, or the file will never be there.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    catalog = (root / "config/artifacts.yaml").read_text()
    artifacts = set(re.findall(r"^  ([a-z0-9][a-z0-9.-]*):$", catalog, re.MULTILINE))

    wanted: set[str] = set()
    for rel in ("install.sh", "scripts/proxy-vm-up.sh"):
        text = (root / rel).read_text()
        code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
        wanted |= set(re.findall(r"BASE=\"\$\{BASE:-([A-Za-z0-9._-]+)\}\"", code))
    assert wanted, "no BASE default found in either script"
    for name in wanted:
        assert name.endswith(".img"), name
        assert name[: -len(".img")] in artifacts, (
            f"{name} is not an artifact in config/artifacts.yaml, so "
            "build-images.py never writes it"
        )


def test_the_state_directory_is_traversable_by_qemu() -> None:
    """The proxy VM would not start on a host that had never run a job.

    QEMU runs as xentry-vm. That user is not xentry and install.sh does not
    put it in the xentry group - it only adds kvm - so to open a disk under
    /var/lib/xentry it must be able to TRAVERSE that directory. At 0750 it
    cannot, libvirt fails to open the overlay, and the domain stays "shut off"
    with a zero-byte console log. The error names the disk, so it reads like a
    missing or corrupt image.

    runtime.py has always granted this per job -
    `parent.chmod(parent.stat().st_mode | 0o001)` in create_vm - which made a
    host that had run even one job silently correct, and hid the bug on every
    host except a freshly installed one. Step 11 runs before the first job.

    o+x is traversal, not listing: jobs/ stays 0750 xentry:xentry and
    artifacts/ 0750 root:xentry, so this exposes nothing underneath.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    install = (root / "install.sh").read_text()
    code = "\n".join(l for l in install.splitlines() if not l.strip().startswith("#"))

    mode = re.search(r'install -d -m (\d+) -o xentry -g xentry "\$STATE"', code)
    assert mode, "the state directory is not created where expected"
    assert mode.group(1) == "0751", f"created {mode.group(1)}, qemu needs o+x"

    # Still private underneath.
    assert 'install -d -m 0750 -o xentry -g xentry "$STATE/jobs"' in code
    assert 'install -d -m 0750 -o root -g xentry "$STATE/artifacts"' in code

    # And the bring-up does not depend on install.sh having done it.
    up = (root / "scripts/proxy-vm-up.sh").read_text()
    upcode = "\n".join(l for l in up.splitlines() if not l.strip().startswith("#"))
    assert "chmod o+x /var/lib/xentry" in upcode

    # The runtime's per-job version must stay too: it covers jobs/ and below.
    runtime = (root / "broker/runtime.py").read_text()
    assert "parent.chmod(parent.stat().st_mode | 0o001)" in runtime


def test_dev_access_refuses_root_and_service_accounts() -> None:
    """DEV=1 resolved the developer to root and reported success.

    sudo sets SUDO_USER=root when ROOT runs sudo, so `sudo DEV=1 ./install.sh`
    from a root shell names root as the developer. The step then did its work
    faithfully: it created xentry-dev with root as its only member, regrouped
    the code trees to it, wrote root two sudo rules it does not need, and told
    root to start a new login shell for a group that grants it nothing.

    The visible result was a tree owned by a group containing only root, so the
    actual human still could not write to it - the one thing the step exists to
    arrange.

    Service accounts are refused for a different reason: xentry, xentry-vm and
    xentry-guest each run one thing with one set of files, and handing one a
    writable code tree plus a sudo rule widens whatever that daemon can be made
    to do. Same for any uid below 1000, which is a system account by
    convention on Debian and Ubuntu.
    """
    import pathlib

    root_dir = pathlib.Path(__file__).resolve().parents[1]
    install = (root_dir / "install.sh").read_text()
    code = "\n".join(l for l in install.splitlines() if not l.strip().startswith("#"))

    assert '[ "$(id -u "$DEV_USER")" -eq 0 ]' in code, "root is still accepted"
    assert '"$DEV_USER" = xentry ' in code or '"$DEV_USER" = xentry]' in code or \
        '[ "$DEV_USER" = xentry ]' in code, "the app service account is still accepted"
    assert '"$DEV_USER" = xentry-vm' in code, "the QEMU account is still accepted"
    assert '[ "$(id -u "$DEV_USER")" -lt 1000 ]' in code, "system accounts are accepted"

    # The refusal has to say how to fix it, or the next person repeats it.
    assert "DEV_USER=<your-login>" in code

    # AND IT HAS TO RUN BEFORE STEP 1. Checking it where it is used meant
    # eleven steps of work - packages, both virtualenvs, eight base images,
    # the services - before being told the developer could not be named.
    preflight = code.index('if [ "$DEV" = 1 ]; then')
    first_step = code.index('step "host packages"')
    assert preflight < first_step, "DEV=1 is validated after work has started"

    # One place only: a second copy is a second thing to keep correct.
    assert code.count('die "DEV=1 needs a human account, not root"') == 1


def test_dev_access_does_not_strip_the_executable_bit() -> None:
    """DEV=1 showed 23 files modified with zero content changed.

    It ran `find "$tree" -type f -exec chmod 664 {} +` over src, tests, broker
    and targets to make them group-writable. 664 is a mode, not a change: it
    cleared the executable bit on every script git records as 100755 - all
    eight run-poc-local-*, and each target's setup.sh, readiness.sh,
    build-poc.sh, null.sh and run-poc.sh.

    Nothing broke, because the broker chmods a step script to 0755 inside the
    guest after copying it in. But `git status` then listed two dozen files as
    modified for a mode the operator never asked to change, which buries any
    real diff - and the next person has to work out whether it mattered.

    g+w ADDS the permission that DEV=1 is for and leaves everything else as it
    found it.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    code = "\n".join(
        l for l in (root / "install.sh").read_text().splitlines()
        if not l.strip().startswith("#")
    )

    assert "-type f -exec chmod g+w" in code, "a blanket file mode is back"
    assert "-type d -exec chmod g+ws" in code, "a blanket directory mode is back"
    for blanket in ("chmod 664", "chmod 2775", "chmod 775", "chmod 644"):
        assert f"-exec {blanket}" not in code, f"{blanket} discards other bits"

    # The scripts that must stay executable, as git has them.
    executable = [
        p for p in (root / "targets").rglob("*.sh")
        if p.stat().st_mode & 0o111
    ]
    assert executable, "no target script is executable; the bit was stripped"


def test_the_bring_up_reads_a_disk_a_vm_may_be_holding() -> None:
    """The run stopped after "exists, keeping it" and said nothing.

    qemu-img info takes a lock on the image, so it fails while a VM holds the
    disk. That is the normal case in the branch that reads it, because the
    branch IS "the disk exists and we are keeping it" - and a kept disk often
    belongs to a VM that is still defined and running. Under
    `set -euo pipefail` the assignment died and took the script with it,
    immediately after the line that says the disk is being kept.

    -U reads the metadata without competing for the lock. Every read of the
    VM's own disk needs it; reads of the pristine base image do not, because
    nothing holds that.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    up = (root / "scripts/proxy-vm-up.sh").read_text()
    code = "\n".join(l for l in up.splitlines() if not l.strip().startswith("#"))

    for match in re.finditer(r'qemu-img info([^\n]*?)"\$RUN/\$VM\.qcow2"', code):
        assert "-U" in match.group(1), (
            "a read of the VM's own disk without -U: it fails while a VM holds it"
        )
    assert code.count('qemu-img info -U "$RUN/$VM.qcow2"') >= 2

    # And the first one reports rather than dying silently.
    assert 'qemu-img could not read the disk:' in code
    assert "sudo virsh destroy" in code


def test_no_silenced_command_substitution_can_kill_a_script() -> None:
    """`x=$(cmd 2>/dev/null)` under set -euo pipefail is the worst shape.

    The assignment's status is the command's, so a failure ends the script -
    and 2>/dev/null has already thrown away the reason. The run stops with
    nothing printed after whatever line came before it.

    That is how the proxy VM bring-up stopped one line after announcing it was
    keeping the existing disk: qemu-img info takes a lock and fails while a VM
    holds the image, and its complaint went to /dev/null.

    Six more had the same shape, every one on a path a fresh install reaches:
    globs for images that do not exist yet (`ls -1 ... *-generic.qcow2`), an
    interface that is not up yet (`ip -4 -o addr show`), ssh to a guest that
    is still booting (`cloud-init status`), `hostname -I` before DHCP, and a
    `find` over directories it may not be able to read.

    `|| true` inside the substitution keeps whatever output there was and
    discards only the status, which is what silencing stderr already implied.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    files = sorted(
        set(root.glob("*.sh")) | set(root.glob("scripts/*.sh"))
        | set(root.glob("deploy/**/*.sh")) | set(root.glob("targets/**/*.sh"))
    )
    sub = re.compile(r"\$\((?:[^()]|\([^()]*\))*\)")
    offenders: list[str] = []
    for path in files:
        text = path.read_text()
        if "pipefail" not in text and "set -e" not in text:
            continue
        joined = re.sub(r"\\\n\s*", " ", text)
        for number, raw in enumerate(joined.splitlines(), 1):
            line = raw.strip()
            if line.startswith("#") or "2>/dev/null" not in line:
                continue
            if not re.match(r"^(local\s+)?[A-Za-z_][A-Za-z_0-9]*=", line):
                continue
            for match in sub.finditer(line):
                body = match.group(0)
                if "2>/dev/null" in body and "||" not in body:
                    offenders.append(f"{path.relative_to(root)}:{number}")
    assert not offenders, (
        "a silenced command substitution in an assignment can end the script "
        "with no reason given: " + ", ".join(sorted(set(offenders)))
    )


def test_uninstall_removes_everything_install_creates() -> None:
    """The two scripts drift, and only one of them is ever run twice.

    install.sh gained a developer-access step, a webfilter, an AppArmor
    drop-in, a second virtualenv and a private Python since uninstall.sh was
    written. Anything it creates that the uninstaller does not name survives a
    "complete" uninstall and is then inherited by the next install, which is
    how a host ends up in a state neither script describes.

    This pairs each thing install.sh makes with the token that removes it.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    install = (root / "install.sh").read_text()
    uninstall = (root / "uninstall.sh").read_text()

    pairs = [
        ("groupadd -f --system xentry", "groupdel"),
        ("groupadd -f xentry-dev", "xentry-dev"),
        ("useradd", "userdel"),
        ('"$STATE"', "$STATE"),
        ('"$ETC"', "$ETC"),
        ("$UVPY", "$UVPY"),
        ("/etc/systemd/system/xentry.service", "xentry*.service"),
        ("10-bind.conf", "xentry*.service.d"),
        ("install-webfilter.sh", "xentry_admin"),
        ("host-wan.nft", "xentry_wan"),
        ("install-apparmor.sh", "apparmor.d/local"),
        ("qemu_conf_set", "qemu.conf.orig"),
        ("/etc/sudoers.d/xentry-dev", "/etc/sudoers.d/xentry-dev"),
        ("/etc/sudoers.d/xentry-read", "/etc/sudoers.d/xentry-read"),
        ("/usr/local/sbin/xentry-read", "/usr/local/sbin/xentry-read"),
        ("proxy-vm-up.sh", "virsh"),
        (".venv-broker", "$APP"),
        ("apt-get install", "apt-mark auto"),
    ]
    missing = [
        f"{made!r} is created but {removed!r} never appears in uninstall.sh"
        for made, removed in pairs
        if made in install and removed not in uninstall
    ]
    assert not missing, "; ".join(missing)
