"""A derived target for a local privilege escalation.

The remote derived path proves "the attacker read a file only the target has".
This one proves "a value only root could read appeared on a channel only root
could write, and the runner read that channel from outside the guest". The
tests here are about where it refuses to go, what the evidence channel is, and
that the control run is checked on the SAME channel as the real one - which is
the fault that would make the whole observation worthless.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

import pytest

from tests.test_generic_target import POC_REPO, GenericBroker, _fetch, _pin_all
from tests.test_runner import fake_validate
from xentry import generic
from xentry.db import connect, init_db
from xentry.jobstore import create_job
from xentry.models import EvidenceRef, Facts
from xentry.runner import JobRunner


def _embedded() -> dict[str, Any]:
    """A PoC that embeds the command root runs, as exim CVE-2019-10149 does."""
    return {
        "poc_command": EvidenceRef(
            artifact_id="poc",
            quote="${run{/bin/sh -c 'id > /tmp/out'}}",
        ),
        "poc_command_exec": "id > /tmp/out",
    }


def _local_facts(**overrides: Any) -> Facts:
    """What the extractor returns for PwnKit-shaped CVE."""
    ref = EvidenceRef(artifact_id="cve", quote="polkit 2.0.0 to 2.1.3 is affected")
    base: dict[str, Any] = {
        "cve_id": "CVE-2026-40404",
        "product": "polkit",
        # The shared fake archive publishes 2.0.9 and nothing else, so the
        # range is written to resolve against it: this module is about the
        # local path, and test_release.py is where version choice is tested.
        "affected_range": "2.0.0 - 2.1.3",
        "version_evidence": [ref],
        "protocol": "local",
        "ports": [],
        "auth_required": False,
        "build_strategy": "pkexec with no argv escalates to root",
        "poc_context": "local",
        "setup_packages": ["policykit-1"],
        "poc_entrypoint": "exploit.c",
        "privesc_shape": "stdin-shell",
        "citations": [ref],
    }
    base.update(overrides)
    return Facts(**base)


# ------------------------------------------------------------- admission ---


def test_a_local_poc_that_names_a_shape_is_admitted() -> None:
    assert generic.admits(_local_facts()) is True
    assert generic.is_local(_local_facts()) is True
    # Every shape picks its own checked-in relay.
    for shape, step in generic.PRIVESC_STEPS.items():
        extra: dict[str, Any] = {"privesc_shape": shape}
        if shape in generic.QUOTED_SHAPES:
            extra |= _embedded()
        target = generic.derive(_local_facts(**extra), POC_REPO)
        assert target.invocation_step_id == step
        assert target.poc.invocation_step_id == step


def test_a_local_poc_with_no_shape_is_refused_and_says_what_is_missing() -> None:
    """The refusal it replaces said the channel had to be designed per CVE.

    The channel is generic - every VM has a serial console wired to a host
    file. What cannot be guessed is how THIS exploit accepts the command that
    carries the proof out, so that is what the refusal now names.
    """
    reason = generic._reason(_local_facts(privesc_shape=None))
    assert reason is not None
    assert "hands over root" in reason
    assert "stdin-shell" in reason and "argv-command" in reason
    assert generic.admits(_local_facts(privesc_shape=None)) is False


def test_a_local_poc_needs_no_port_and_no_network_protocol() -> None:
    """Both were blanket refusals before, and neither applies to a local PoC:
    nothing listens, and nothing is reached over the network."""
    facts = _local_facts(ports=[], protocol="local")
    assert generic.admits(facts) is True
    target = generic.derive(facts, POC_REPO)
    assert target.target_ports == ()
    assert target.attacker_profile_id is None
    # And a remote PoC with no port is still refused, as it was.
    remote = _local_facts(poc_context="remote", protocol="tcp", ports=[], privesc_shape=None)
    assert generic.admits(remote) is False


def test_the_local_target_proves_it_with_a_root_only_secret() -> None:
    target = generic.derive(_local_facts(), POC_REPO)
    # 0644 in /var/lib is right for the remote proof - any read primitive can
    # see it - and worthless here, where reading it IS the privilege.
    assert target.nonce.path == "/root/xentry-nonce"
    assert target.nonce.mode == 0o600
    assert target.nonce.owner == "root"
    assert target.evidence_channel.kind == "host_serial"
    assert target.evidence_channel.channel == "org.xentry.evidence.0"
    assert target.decisive_probe().step_id == "probe-generic-serial"
    assert target.null_actor.location == "target"
    assert target.readiness_step_id == "readiness-local"
    assert any("only root could read" in line for line in target.what_proves)
    assert any("unforgeable" in line for line in target.what_does_not_prove)


def test_every_local_step_is_in_the_manifest_and_the_registry() -> None:
    """The four tables that have to agree, for the four new steps.

    A step the manifest describes but the broker's own allowlist omits is
    refused at the first provisioning call, which is how every derived job
    died once before.
    """
    from broker.registry import STEPS, resolve_step
    from broker.steps import StepRegistry

    registry = StepRegistry(Path("targets/steps.yaml"), Path("targets"))
    wanted = {
        "readiness-local": ("package", "expected_version", "cve_id"),
        "null-local": ("nonce_path",),
        "run-poc-local-stdin": ("poc_dir", "entrypoint", "nonce_path"),
        "run-poc-local-argv": ("poc_dir", "entrypoint", "nonce_path"),
    }
    for step_id, params in wanted.items():
        assert step_id in STEPS, step_id
        # Not a setup step, so it runs as the unprivileged actor - which is
        # the whole point: a relay run as root would prove nothing.
        assert resolve_step(step_id).allowed_users == ("xentry-guest",), step_id
        spec = registry.get(step_id)
        assert spec.params == params, step_id
        assert spec.user == "xentry-guest", step_id


# ------------------------------------------------------------------ a job ---


class LocalBroker(GenericBroker):
    """A broker for a local job: the exploit writes the serial, or does not."""

    def __init__(self, *, escalates: bool = True, leaky_null: bool = False) -> None:
        super().__init__()
        self.escalates = escalates
        self.leaky_null = leaky_null
        self.serial = ""
        self.rebooted = False

    def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
        if verb == "create_attacker":
            raise AssertionError("a local job must not build an attacker VM")
        if verb == "snapshot":
            raise AssertionError("a local job has nothing to snapshot")
        if verb == "reboot":
            # The broker waits for SSH and reads the new boot_id; a kernel job
            # is only the thing under test after this.
            self.calls.append((verb, params))
            self.rebooted = True
            return {"vm_id": params["vm_id"], "boot_id": "boot-2", "state": "running"}
        if verb == "read_host_evidence":
            assert params["channel"] == "org.xentry.evidence.0"
            data = self.serial.encode()
            return {
                "bytes_b64": base64.b64encode(data).decode("ascii"),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        if verb == "place_nonce":
            assert params["path"] == "/root/xentry-nonce"
            assert params["mode"] == 0o600
            if self.leaky_null and str(params["nonce_id"]).startswith("null-"):
                # The failure this exists to catch: something reaches the
                # console with no exploit at all.
                self.serial += f"xentry-root-evidence:{params['value']}\n"
            return super().call(verb, params, **kwargs)
        if verb == "exec":
            self.exec_params[str(params.get("step_id"))] = dict(params.get("params") or {})
            if str(params.get("step_id")) in generic.PRIVESC_STEPS.values():
                if self.escalates:
                    self.serial += f"xentry-root-evidence:{self.nonce}\n"
                return {"exit_code": 0, "stdout": "uid=0", "stderr": "", "duration_ms": 1}
            return {"exit_code": 0, "stdout": "ok", "stderr": "", "duration_ms": 1}
        return super().call(verb, params, **kwargs)


def _run_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, broker: LocalBroker, **overrides: Any
) -> tuple[str, Path]:
    _pin_all(monkeypatch)
    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, attempt_dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_REPO, cve_url="https://example.com/cve"
    )
    conn.close()
    JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=lambda _artifacts: _local_facts(**overrides),
        validate_fn=fake_validate,
        fetch_fn=_fetch,
        broker_factory=lambda: broker,
    ).run_job(job_id, "https://example.com/cve", POC_REPO, attempt_id)
    return job_id, attempt_dir


def _outcome(tmp_path: Path, job_id: str) -> tuple[str, str]:
    conn = connect(tmp_path / "xentry.db")
    try:
        row = conn.execute(
            "SELECT outcome, reason_code FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
    finally:
        conn.close()
    return str(row["outcome"]), str(row["reason_code"] or "")


def test_a_local_job_runs_on_the_target_and_is_decided_by_the_serial_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = LocalBroker()
    job_id, _dir = _run_local(tmp_path, monkeypatch, broker)
    assert _outcome(tmp_path, job_id)[0] == "completed"

    # The relay was handed the root-only path and the PoC directory, and no
    # port or target_ip: there is no second machine in this job.
    relay = broker.exec_params["run-poc-local-stdin"]
    assert relay["nonce_path"] == "/root/xentry-nonce"
    assert relay["entrypoint"] == "exploit.c"
    assert "port" not in relay and "target_ip" not in relay

    # The null actor was asked to try both halves with no exploit.
    assert broker.exec_params["null-local"] == {"nonce_path": "/root/xentry-nonce"}
    # Readiness took no ports and did assert the installed version.
    assert set(broker.exec_params["readiness-local"]) == {
        "package", "expected_version", "cve_id",
    }
    # The CVE id travels so readiness can ask the installed package's own
    # changelog whether this fix is already backported into it.
    assert broker.exec_params["readiness-local"]["cve_id"] == "CVE-2026-40404"

    # And the toolchain travelled with the packages, from the same serial.
    packages = broker.exec_params["setup-generic"]["packages"].split()
    assert "policykit-1" in packages
    assert "build-essential" in packages


def test_an_exploit_that_never_reaches_the_console_does_not_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No fallback to the transcript.

    The PoC exits 0 and prints uid=0, which is the guest's own word for it.
    Falling back to that is what makes a decisive channel optional, and it is
    exactly how a local job could report a reproduction nobody witnessed.
    """
    broker = LocalBroker(escalates=False)
    job_id, _dir = _run_local(tmp_path, monkeypatch, broker)
    outcome, reason = _outcome(tmp_path, job_id)
    assert outcome == "failed"
    assert reason == "nonce_not_observed"


def test_a_console_the_null_actor_can_reach_fails_the_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control has to be checked on the DECISIVE channel.

    probe_null only ever read the actor's transcript. For a local job the
    transcript is not what decides, so a console the unprivileged actor could
    already write would have passed the control and then "proved" the
    escalation on the real run.
    """
    broker = LocalBroker(leaky_null=True)
    job_id, _dir = _run_local(tmp_path, monkeypatch, broker)
    outcome, reason = _outcome(tmp_path, job_id)
    assert outcome == "failed"
    assert reason == "null_actor_observed_nonce"


def test_a_remote_derived_job_is_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The remote path keeps its attacker, its port and its transcript."""
    from tests.test_generic_target import _facts, _run

    job_id, _dir, broker = _run(tmp_path, _facts(), monkeypatch)
    assert _outcome(tmp_path, job_id)[0] == "completed"
    relay = broker.exec_params["run-poc-generic"]
    assert relay["port"] == "8080"
    assert relay["target_ip"]
    assert "create_attacker" in [verb for verb, _params in broker.calls]


def test_a_compiled_poc_names_the_binary_not_the_source() -> None:
    """The run step would have done `exec ./hax.c`.

    blasty/CVE-2021-3156 ships hax.c and a Makefile saying
    `gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c`, and the extractor answered
    poc_entrypoint "hax.c" - which the build step then required to exist
    BEFORE running make, and the run step then tried to execute. Three places
    had to change: the prompt says the entrypoint is what runs, the build step
    requires it after the build and lists what it did produce, and the run
    steps refuse a non-executable rather than failing as "cannot execute
    binary file".
    """
    from xentry.extract import _prompt

    prompt = _prompt([])
    assert "sudo-hax-me-a-sandwich" in prompt
    assert "the name after -o" in prompt

    build = Path("targets/common/build-poc-generic.sh").read_text()
    # The build runs first; the entrypoint is required after it.
    assert build.index("make") < build.index("the build produced no")
    assert "Executable files here" in build

    for name in (
        "run-poc-local-stdin.sh",
        "run-poc-local-argv.sh",
        "run-poc-generic.sh",
    ):
        script = Path("targets/common") / name
        body = script.read_text()
        assert "not runnable" in body, name
        # And an interpreted entrypoint is still only required to exist, since
        # it runs through python3 or bash rather than on its own.
        assert "*.py|*.sh|*.rb|*.pl|*.js|*.php" in body, name


def test_the_manifest_pins_what_the_scripts_now_are() -> None:
    """A step script whose hash drifts from the manifest is refused by the
    broker at the first exec, which is how a whole class of jobs died once."""
    import hashlib

    import yaml

    from broker.steps import StepRegistry

    manifest = yaml.safe_load(Path("targets/steps.yaml").read_text())
    for step_id, spec in manifest["steps"].items():
        body = (Path("targets") / spec["script"]).read_bytes()
        assert hashlib.sha256(body).hexdigest() == spec["sha256"], step_id
    # And the loader agrees, which is the check the broker itself runs.
    StepRegistry(Path("targets/steps.yaml"), Path("targets"))


def test_a_kernel_cve_runs_locally_and_is_refused_remotely() -> None:
    """Route B1. Installing a linux-image .deb does not change the RUNNING
    kernel - only a reboot does - so a kernel CVE is admitted exactly where
    the reboot and the uname assertion are.

    On the local path: setup installs it, updates the initramfs and grub and
    records which kernel it added, the runner reboots, and readiness refuses
    to continue unless `uname -r` IS that kernel. A remote kernel CVE has none
    of that and no observation design either, so it still refuses - without
    the guard an approved kernel .deb installed, the VM kept running the
    image's own kernel, and the job reported on a kernel that never ran.
    """
    for overrides in (
        {"setup_packages": ["linux-image-amd64"]},
        {"setup_packages": ["linux-image-5.16.0-5-amd64", "linux-modules-5.16.0-5"]},
        {"product": "Linux kernel", "setup_packages": ["sudo"]},
    ):
        local = _local_facts(**overrides)
        assert generic.is_kernel(local) is True, overrides
        assert generic.admits(local) is True, overrides
        remote = _local_facts(
            poc_context="remote", protocol="http", ports=[80],
            privesc_shape=None, **overrides,
        )
        reason = generic._reason(remote)
        assert reason is not None, overrides
        assert "never booted" in reason
    # And a package whose name merely contains "linux" is not a kernel.
    assert generic.is_kernel(_local_facts(setup_packages=["linux-libc-dev"])) is False
    assert generic.admits(_local_facts(setup_packages=["linux-libc-dev"])) is True


def test_a_guest_that_panics_mid_exploit_is_a_result_not_a_broker_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A kernel exploit that fails usually takes the VM with it.

    That arrived as an SSH error through the broker - which is exactly what
    the broker breaking looks like - so "the exploit crashed the kernel" and
    "the harness is broken" were reported identically, and only one of them
    is an experimental result. The console already had the panic.
    """
    from xentry.broker import BrokerError

    class PanicBroker(LocalBroker):
        def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
            if verb == "exec" and str(params.get("step_id")) in (
                generic.PRIVESC_STEPS.values()
            ):
                self.serial += (
                    "[   12.345678] BUG: unable to handle page fault for address\n"
                    "[   12.345679] Kernel panic - not syncing: Fatal exception\n"
                )
                raise BrokerError("exec_failed", "ssh: connection reset by peer")
            return super().call(verb, params, **kwargs)

    broker = PanicBroker()
    job_id, _dir = _run_local(tmp_path, monkeypatch, broker)
    outcome, reason = _outcome(tmp_path, job_id)
    assert outcome == "failed"
    assert reason == "target_panicked"

    conn = connect(tmp_path / "xentry.db")
    try:
        row = conn.execute(
            "SELECT detail FROM job_steps WHERE reason_code='target_panicked'"
        ).fetchone()
    finally:
        conn.close()
    # The panic text travels, so the reader sees what the kernel said.
    assert row is not None
    assert "Kernel panic - not syncing" in str(row["detail"])


def test_an_ssh_failure_with_no_panic_is_still_a_broker_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reclassification must not swallow real broker faults."""
    from xentry.broker import BrokerError

    class DeadBroker(LocalBroker):
        def call(self, verb: str, params: dict[str, Any], **kwargs: Any) -> Any:
            if verb == "exec" and str(params.get("step_id")) in (
                generic.PRIVESC_STEPS.values()
            ):
                raise BrokerError("exec_failed", "ssh: connection reset by peer")
            return super().call(verb, params, **kwargs)

    broker = DeadBroker()
    job_id, _dir = _run_local(tmp_path, monkeypatch, broker)
    outcome, reason = _outcome(tmp_path, job_id)
    assert outcome == "failed"
    assert reason == "exec_failed"


def test_the_panic_reader_finds_each_marker_and_nothing_else() -> None:
    from xentry.runner import panic_in

    for marker in (
        "Kernel panic - not syncing: Fatal exception",
        "BUG: unable to handle page fault",
        "general protection fault: 0000 [#1] SMP",
        "Oops: 0002 [#1] SMP PTI",
    ):
        found = panic_in(f"[   1.0] boot\n[  12.3] {marker}\nmore\n")
        assert marker in found, marker
    assert panic_in("") == ""
    assert panic_in("[ 1.0] systemd: ready\nexploit failed\n") == ""


def test_a_fixed_command_poc_needs_the_command_and_the_span() -> None:
    """The third shape: the PoC hands the caller no way to run anything.

    aishee's exim CVE-2019-10149 PoC sends a crafted recipient address and
    root executes a command the PoC itself contains, so the relay has to be
    substituted INTO its own text. The quote locates the file that holds it -
    one file, or the step refuses - and the span is the only text replaced.
    Both come verified against the artifact, so neither is text a model wrote.
    """
    shaped = _local_facts(privesc_shape="fixed-command", **_embedded())
    assert generic.admits(shaped) is True
    assert generic.derive(shaped, POC_REPO).invocation_step_id == "run-poc-local-patch"

    # No command quoted at all, for either shape that needs one.
    for shape in generic.QUOTED_SHAPES:
        bare = _local_facts(privesc_shape=shape)
        reason = generic._reason(bare)
        assert reason is not None and "command quoted from the" in reason, shape

    # A span that is not inside the quoted command cannot be substituted.
    wrong = _local_facts(
        privesc_shape="fixed-command",
        poc_command=_embedded()["poc_command"],
        poc_command_exec="whoami",
    )
    assert generic.admits(wrong) is False


def test_the_fixed_command_step_is_handed_the_quote_and_the_span(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = LocalBroker()
    job_id, _dir = _run_local(
        tmp_path, monkeypatch, broker, privesc_shape="fixed-command", **_embedded()
    )
    assert _outcome(tmp_path, job_id)[0] == "completed"
    params = broker.exec_params["run-poc-local-patch"]
    assert params["command"] == "${run{/bin/sh -c 'id > /tmp/out'}}"
    assert params["span"] == "id > /tmp/out"
    assert params["nonce_path"] == "/root/xentry-nonce"
    assert "port" not in params


def test_the_patch_step_replaces_only_the_span(tmp_path: Path) -> None:
    """Rehearsed against a real file, because a substitution that breaks the
    PoC's own syntax would look like a PoC that does not work.

    The replacement carries no quotes of its own: the span usually sits inside
    a quoted string in someone else's source, as it does here.
    """
    import subprocess

    poc = tmp_path / "poc"
    poc.mkdir()
    (poc / "exploit.py").write_text(
        'payload = "${run{/bin/sh -c \'id > /tmp/out\'}}"\n'
        'open("/tmp/sent", "w").write(payload)\n'
    )
    (poc / "README.md").write_text("Run exploit.py; the MTA runs `id` as root.\n")
    done = subprocess.run(
        [
            "bash",
            str(Path("targets/common/run-poc-local-patch.sh").resolve()),
            str(poc),
            "exploit.py",
            "/root/xentry-nonce",
            "${run{/bin/sh -c 'id > /tmp/out'}}",
            "id > /tmp/out",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    patched = (poc / "exploit.py").read_text()
    assert "cat /root/xentry-nonce >/dev/ttyS0" in patched, done.stderr
    # Still syntactically the same payload, with one span swapped.
    assert patched.startswith('payload = "${run{/bin/sh -c \'cat ')
    assert "id > /tmp/out" not in patched


def test_a_kernel_job_reboots_between_setup_and_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Route B1's whole point, in the order it has to happen.

    The kernel is installed, then the machine is rebooted into it, and only
    then is readiness asked whether it booted. A reboot after readiness, or
    none at all, would assert against the image's own kernel.
    """
    broker = LocalBroker()
    job_id, _dir = _run_local(
        tmp_path, monkeypatch, broker, setup_packages=["linux-image-amd64"]
    )
    assert _outcome(tmp_path, job_id)[0] == "completed"

    conn = connect(tmp_path / "xentry.db")
    try:
        rows = [
            (str(row["name"]), str(row["step_id"] or ""))
            for row in conn.execute(
                "SELECT name, step_id FROM job_steps WHERE job_id=? ORDER BY seq",
                (job_id,),
            )
        ]
    finally:
        conn.close()
    names = [name for name, _step in rows]
    assert "reboot" in names, names
    assert names.index("provision") < names.index("reboot") < names.index("readiness")
    # Recorded under its own step id, not dirtyfrag's.
    assert ("reboot", "reboot-generic") in rows

    # And the toolchain still travelled, so a C exploit can build.
    packages = broker.exec_params["setup-generic"]["packages"].split()
    assert "linux-image-amd64" in packages and "build-essential" in packages


def test_an_ordinary_local_job_does_not_reboot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reboot costs two boots and throws away the provisioned state's
    uptime; only a kernel job earns one."""
    broker = LocalBroker()
    job_id, _dir = _run_local(tmp_path, monkeypatch, broker)
    assert _outcome(tmp_path, job_id)[0] == "completed"
    assert "reboot" not in [verb for verb, _params in broker.calls]


def test_setup_records_the_kernel_it_added_not_the_newest() -> None:
    """The base image ships its own kernel.

    Picking the newest installed would assert the wrong one whenever the
    affected kernel is the older of the two - and then the job would report a
    result about a kernel that was never booted, which is the exact failure
    this route exists to avoid. The step records what IT added, and readiness
    compares against that; if grub booted something else, readiness fails and
    says so.
    """
    setup = Path("targets/common/setup-generic.sh").read_text()
    assert "kernels_before" in setup
    assert setup.index("kernels_before") < setup.index("apt-get install")
    assert "update-initramfs -u -k all" in setup
    assert "update-grub" in setup
    assert "/var/lib/xentry/kernel.want" in setup

    readiness = Path("targets/common/readiness-local.sh").read_text()
    assert "kernel.want" in readiness
    assert "is not the installed" in readiness


def test_a_real_filename_with_parentheses_is_not_refused() -> None:
    """CVE-2022-24112's PoC is `Apache_APISIX_RCE(CVE-2022-24112).py`.

    The entrypoint pattern allowed only letters, digits, dot, underscore,
    slash and dash, so that file - the one thing in the repository that runs
    the exploit - was refused and the CVE with it. It is safe to allow:
    broker/runtime.py shlex.quotes every step parameter and the scripts read
    "./$entrypoint", so these are argv bytes, never shell syntax.
    """
    ok = _local_facts(poc_entrypoint="Apache_APISIX_RCE(CVE-2022-24112).py")
    assert generic.entrypoint(ok) == "Apache_APISIX_RCE(CVE-2022-24112).py"
    for name in ("exploit+poc.py", "run@2.sh", "cve-2021-4034.c", "a/b/exp.py"):
        assert generic.entrypoint(_local_facts(poc_entrypoint=name)) == name
    # Traversal and absolute paths are still refused, before any trimming.
    for bad in ("/etc/passwd", "../x.py", "./../x.py", "a/../../etc/shadow"):
        with pytest.raises(generic.NoObservable):
            generic.entrypoint(_local_facts(poc_entrypoint=bad))
    # And a shell metacharacter that is not in a filename stays out.
    for bad in ("exp;rm -rf /", "a`id`.py", "$(id).py", "a|b.py"):
        with pytest.raises(generic.NoObservable):
            generic.entrypoint(_local_facts(poc_entrypoint=bad))


def _staged() -> dict[str, Any]:
    """CVE-2023-0386: a FUSE mount has to be up before ./exp works."""
    return {
        "poc_command": EvidenceRef(
            artifact_id="poc", quote="./fuse ./ovlcap/lower ./gc"
        ),
    }


def test_a_two_stage_poc_runs_its_helper_first() -> None:
    """Neither half alone is the PoC.

    CVE-2023-0386's README says `./fuse ./ovlcap/lower ./gc` and then
    `./exp` - a mount that must stay up, then the exploit. The helper line is
    a command WITH ARGUMENTS, so it comes from a verified quote exactly as the
    fixed-command shape's does: the harness runs text the PoC's own
    documentation contains, and nothing else.
    """
    staged = _local_facts(privesc_shape="two-stage", **_staged())
    assert generic.admits(staged) is True
    target = generic.derive(staged, POC_REPO)
    assert target.invocation_step_id == "run-poc-local-stage"
    # And with no quoted command there is no helper to start.
    bare = _local_facts(privesc_shape="two-stage")
    reason = generic._reason(bare)
    assert reason is not None and "starts the helper" in reason


def test_the_stage_step_is_handed_the_helper_line_and_no_span(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker = LocalBroker()
    job_id, _dir = _run_local(
        tmp_path, monkeypatch, broker, privesc_shape="two-stage", **_staged()
    )
    assert _outcome(tmp_path, job_id)[0] == "completed"
    params = broker.exec_params["run-poc-local-stage"]
    assert params["command"] == "./fuse ./ovlcap/lower ./gc"
    # span belongs to fixed-command, where a span is substituted; here the
    # whole line is run.
    assert "span" not in params


def test_the_stage_script_refuses_a_command_that_is_not_one_file_and_arguments(
    tmp_path: Path,
) -> None:
    """Validated in the script as well as at admission, because a step script
    is the last place that can refuse."""
    import subprocess

    poc = tmp_path / "poc"
    poc.mkdir()
    (poc / "helper.sh").write_text("#!/bin/bash\necho up; sleep 5\n")
    (poc / "exp").write_text("#!/bin/bash\ncat\n")
    (poc / "exp").chmod(0o755)
    script = Path("targets/common/run-poc-local-stage.sh").resolve()
    for bad in ("./helper.sh; id", "./helper.sh | id", "id", "/bin/sh", "./../x"):
        done = subprocess.run(
            ["bash", str(script), str(poc), "exp", "/root/xentry-nonce", bad],
            capture_output=True, text=True, check=False,
        )
        assert done.returncode == 2, (bad, done.stdout, done.stderr)
        assert "refused stage command" in done.stderr, bad


def test_the_build_step_says_which_build_it_cannot_do(tmp_path: Path) -> None:
    """Three different gaps used to read as one failed build.

    A Maven tree was not attempted at all and the run step then said "not
    runnable: src/main/java/.../Main.java"; a Go PoC with no toolchain and one
    with unvendored modules were the same error. Each says what it is now, and
    what the operator can do - which for Maven is approve the built .jar,
    because this harness has dated proxies for apt, npm, pypi and container
    images and none for Maven.
    """
    import subprocess

    script = Path("targets/common/build-poc-generic.sh").resolve()

    def run(files: dict[str, str], entrypoint: str) -> subprocess.CompletedProcess[str]:
        poc = tmp_path / entrypoint.replace("/", "_")
        src = poc / "src"
        src.mkdir(parents=True)
        for name, body in files.items():
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            (src / name).write_text(body)
        archive = poc / "poc.tar.gz"
        subprocess.run(
            ["tar", "-czf", str(archive), "-C", str(poc), "src"], check=True
        )
        digest = subprocess.run(
            ["sha256sum", str(archive)], capture_output=True, text=True, check=True
        ).stdout.split()[0]
        return subprocess.run(
            [
                "bash", str(script), str(archive), digest,
                str(poc / "out"), entrypoint,
            ],
            capture_output=True, text=True, check=False,
        )

    maven = run({"pom.xml": "<project/>", "Main.java": "class Main {}"}, "Main.java")
    assert maven.returncode == 1
    assert "Maven or Gradle" in maven.stderr
    assert "approve the built .jar" in maven.stderr

    go = run({"go.mod": "module poc\n", "main.go": "package main\n"}, "poc-bin")
    assert go.returncode == 1
    # Either no toolchain or no vendored modules, depending on the host, and
    # both name the way out.
    assert "Go" in go.stderr
    assert ("no toolchain" in go.stderr) or ("does not vendor" in go.stderr)


def test_the_changelog_check_catches_a_backported_fix(tmp_path: Path) -> None:
    """The hole three ADR entries could only warn about.

    A stable series keeps the upstream version and backports the patch, so
    2.4.48-3.1+deb11u1 satisfies every version check this harness can make and
    reproduces nothing - the job runs, the exploit fails, and the report says
    "did not reproduce", which is indistinguishable from a PoC that does not
    work. Debian and Ubuntu cite the CVE id in the changelog entry of the
    update that fixed it, so the installed package can simply be asked.
    """
    import gzip
    import subprocess

    doc = tmp_path / "usr/share/doc/widget"
    doc.mkdir(parents=True)
    (doc / "changelog.Debian.gz").write_bytes(
        gzip.compress(
            b"widget (2.4.48-3.1+deb11u1) bullseye-security; urgency=high\n"
            b"  * Fix CVE-2021-41773: path traversal in mod_proxy\n"
        )
    )
    body = Path("targets/common/readiness-local.sh").read_text()
    # Run only the changelog block, with the host checks stubbed out.
    body = body.replace("/usr/share/doc", str(tmp_path / "usr/share/doc"))
    for stub in (
        "test -f /var/lib/xentry/setup-generic.done",
        'test "$(id -u)" -ne 0',
        "test -e /dev/ttyS0",
        "test ! -w /dev/ttyS0",
        "test ! -r /root",
    ):
        body = "\n".join(
            "true" if line.startswith(stub) else line for line in body.splitlines()
        )
    script = tmp_path / "readiness.sh"
    script.write_text(body)

    named = subprocess.run(
        ["bash", str(script), "widget", "", "CVE-2021-41773"],
        capture_output=True, text=True, check=False,
    )
    assert named.returncode == 1
    assert "carries the fix" in named.stderr

    other = subprocess.run(
        ["bash", str(script), "widget", "", "CVE-2022-0847"],
        capture_output=True, text=True, check=False,
    )
    assert other.returncode == 0, other.stderr
    assert "does not name CVE-2022-0847" in other.stdout

    # And a package with no changelog cannot be judged, which is said rather
    # than assumed either way.
    missing = subprocess.run(
        ["bash", str(script), "absent-package", "", "CVE-2022-0847"],
        capture_output=True, text=True, check=False,
    )
    assert missing.returncode == 0
    assert "cannot check whether the fix is backported" in missing.stdout


def test_a_single_c_file_with_no_makefile_says_what_is_missing(tmp_path: Path) -> None:
    """CVE-2016-5195's flags live in its README: `gcc -pthread dirty.c -o
    dirty -lcrypt`. The harness will not guess a link line, because a wrong
    one is a compile error attributed to the CVE."""
    import subprocess

    src = tmp_path / "src"
    src.mkdir()
    (src / "dirty.c").write_text("int main(){return 0;}\n")
    archive = tmp_path / "poc.tar.gz"
    subprocess.run(["tar", "-czf", str(archive), "-C", str(tmp_path), "src"], check=True)
    digest = subprocess.run(
        ["sha256sum", str(archive)], capture_output=True, text=True, check=True
    ).stdout.split()[0]
    done = subprocess.run(
        [
            "bash", str(Path("targets/common/build-poc-generic.sh").resolve()),
            str(archive), digest, str(tmp_path / "out"), "dirty",
        ],
        capture_output=True, text=True, check=False,
    )
    assert done.returncode == 1
    assert "C source here and no Makefile" in done.stderr
    assert "Approve a built binary" in done.stderr


def test_the_attacker_takes_its_pip_packages_from_the_dated_index() -> None:
    """CVE-2023-48795 passed sixteen steps and died on an import.

    `from termcolor import colored` on line 9. The attacker image carries
    colorama and not termcolor - two cosmetic colour libraries, and the PoC
    picked the other one - and the network is locked before the exploit runs,
    so nothing can be fetched later. The image's own docstring records the same
    thing happening once before: "CVE-2026-56290's PoC needs requests and
    colorama; the image carried only the first."

    A pinned wheel in the image cannot be the answer: it would install one
    undated version for every job, whatever the advisory's date. The registry
    proxy already filters PyPI by upload-time - it was built for the npm path
    and the PyPI half had no caller at all - so the attacker installs what
    PyPI held one day before the advisory, which is the rule the apt side has
    always followed.
    """
    import yaml

    from xentry import generic

    root = Path(__file__).resolve().parents[1]
    manifest = yaml.safe_load((root / "targets/steps.yaml").read_text())["steps"]
    # Both entries drive the same script, so both carry the two new params and
    # the first eleven keep their positional meaning.
    for name in ("setup-generic", "setup-attacker"):
        assert manifest[name]["params"][-2:] == ["registry_url", "pip_packages"], name
        assert manifest[name]["script"] == "common/setup-generic.sh"

    # A PyPI name is not an apt name: PEP 503 allows any case, dots and
    # underscores, so PACKAGE_RE would refuse half of them.
    for good in ("termcolor", "zope.interface", "Flask", "beautifulsoup4", "py-cpuinfo"):
        assert generic.tokens([good], "pip") == good, good
    for bad in ("../etc/passwd", "a b", "x;y", "http://e", "-lead"):
        with pytest.raises(generic.NoObservable):
            generic.tokens([bad], "pip")


def test_the_setup_script_refuses_pip_without_a_proxy() -> None:
    """Named pip packages and no index is a refusal, not a silent skip.

    The guest has no route to pypi.org - the proxy is the only index it can
    reach - so installing from anywhere else is not a fallback, it is a
    different job.
    """
    root = Path(__file__).resolve().parents[1]
    script = (root / "targets/common/setup-generic.sh").read_text()
    assert 'registry_url="${12-}"' in script
    assert 'pip_packages="${13-}"' in script
    assert "--index-url" in script
    assert "registry_url is not a proxy url" in script
    # The name check happens before any name reaches a command line.
    assert "bad pip package" in script
