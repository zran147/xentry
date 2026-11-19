"""The tool layer is the trust boundary, so these test the boundary.

ADR 0004 asks specifically that `place_nonce` be shown *unreachable* rather
than merely unoffered - asserted against the allowlist, not against whatever
tool list a loop happens to advertise. A model that could place or read the
nonce would make every verdict in this system worthless, so the property has
to survive someone adding a phase.
"""

from __future__ import annotations

from typing import Any

import pytest

from xentry.harness import EXPLORE_TOOLS, NEVER, PHASE_TOOLS, ToolLayer, ToolRefused


class Spy:
    """A broker that records what reached it, so a refusal can be proven."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, verb: str, params: dict[str, Any]) -> dict[str, Any]:
        self.seen.append((verb, params))
        return {"ok": True}


def _layer(phase: str = "explore") -> tuple[ToolLayer, Spy]:
    spy = Spy()
    return (
        ToolLayer(call_broker=spy, job_id="job-1", target_vm_id="vm-target", phase=phase),
        spy,
    )


def test_no_phase_can_reach_a_forbidden_verb() -> None:
    """The property asserted against the TABLE, so a new phase cannot open it.

    Checking that a particular loop does not offer place_nonce would pass
    while a second phase quietly granted it. This iterates every phase that
    exists and intersects it with the forbidden set, so adding
    PHASE_TOOLS["verify"] = {...place_nonce...} fails here rather than in
    production.
    """
    assert "place_nonce" in NEVER
    for phase, tools in PHASE_TOOLS.items():
        overlap = tools & NEVER
        assert not overlap, f"phase {phase!r} grants {sorted(overlap)}"


def test_a_forbidden_verb_never_reaches_the_broker() -> None:
    """Refused, not forwarded. The spy proves nothing was sent."""
    layer, spy = _layer()
    for verb in sorted(NEVER):
        with pytest.raises(ToolRefused) as refusal:
            layer.call(verb, {"vm_id": "vm-target"})
        # The message must distinguish "never" from "not in this phase", or a
        # model keeps retrying one of them until its budget is gone.
        assert "at all" in str(refusal.value), verb
    assert spy.seen == [], "a forbidden verb was forwarded"


def test_an_unknown_phase_offers_nothing() -> None:
    """Fail closed. A phase nobody has defined must not inherit explore's set."""
    layer, spy = _layer(phase="verify")
    with pytest.raises(ToolRefused) as refusal:
        layer.call("free_exec_target", {"command": "id"})
    assert "verify" in str(refusal.value)
    assert spy.seen == []


def test_the_model_cannot_choose_which_vm_it_drives() -> None:
    """The subject comes from state, never from the call.

    This is the other half of ADR 0004's restriction: a tool call naming the
    attacker must reach the target or nothing. The broker checks the role
    again on its side, which is deliberate duplication - an allowlist with one
    copy is one refactor away from being bypassed.
    """
    layer, spy = _layer()
    # A free command names its role in the verb and carries a job, not a VM:
    # the broker resolves jobs_root/<job>/target/state.json itself, so there is
    # no vm_id for a model to get wrong and no role check to forget.
    layer.call("free_exec_target", {"job_id": "somebody-elses", "command": "id"})
    verb, sent = spy.seen[0]
    assert verb == "free_exec_target"
    assert sent["job_id"] == "job-1", "the model's job_id was honoured"
    assert "vm_id" not in sent
    assert sent["command"] == "id"
    # Every other tool still addresses a VM, and that id is substituted too.
    layer.call("http_probe", {"vm_id": "vm-attacker", "port": 80})
    assert spy.seen[1][1]["vm_id"] == "vm-target"


def test_every_offered_tool_is_a_real_broker_verb() -> None:
    """A typo in the allowlist is a tool the model is told it has.

    It would then spend calls on a verb the broker rejects as unknown, and the
    refusal would come from the wrong layer with the wrong explanation.
    """
    from broker.main import VERB_PARAMS

    missing = sorted(EXPLORE_TOOLS - set(VERB_PARAMS))
    assert not missing, f"offered but not broker verbs: {missing}"


def test_what_the_model_may_drive_is_exactly_what_was_decided() -> None:
    """Pinned against ADR 0004's table, so a widening is a deliberate edit.

    readiness is absent on purpose: it is not a broker verb, so it reaches the
    model as a tool the runner implements rather than as a forwarded call.
    """
    assert EXPLORE_TOOLS == {
        "free_exec_target",
        "copy_in",
        "copy_out",
        "http_probe",
        "snapshot",
        "restore",
        "reboot",
    }
    for withheld in ("place_nonce", "exec", "lock_network", "read_host_evidence"):
        assert withheld in NEVER, withheld


def test_every_call_is_recorded_for_the_session() -> None:
    """The session feed is hash-chained, so the layer must hand it every call.

    A tool call that bypasses the recorder is a command that ran and left no
    trace, which is the one thing a mode built on "a model ran commands and we
    kept the receipts" cannot afford.
    """
    noted: list[tuple[str, dict[str, Any]]] = []
    spy = Spy()
    layer = ToolLayer(
        call_broker=spy,
        job_id="job-1",
        target_vm_id="vm-target",
        record=lambda verb, params: noted.append((verb, params)),
    )
    layer.call("free_exec_target", {"command": "id"})
    layer.call("http_probe", {"port": 80})
    assert [verb for verb, _ in noted] == ["free_exec_target", "http_probe"]
    # Recorded with the SUBSTITUTED subject, so the record says what really ran.
    assert noted[0][1]["job_id"] == "job-1"
    assert noted[1][1]["vm_id"] == "vm-target"
    assert len(layer.calls) == 2


def test_the_attacker_verb_exists_but_is_offered_to_nobody() -> None:
    """Declared for a later phase, reachable from none of them today.

    It is deliberately NOT in NEVER: a later phase wants free_exec_attacker
    legitimately, and putting it there would make granting it look like
    loosening a prohibition rather than extending a phase. So the property is
    that no phase offers it YET, which is weaker than NEVER and honest about
    being weaker.
    """
    from broker.main import VERB_PARAMS

    assert "free_exec_attacker" in VERB_PARAMS, "the broker should declare it"
    assert "free_exec_attacker" not in NEVER, "a later phase wants it"
    for phase, tools in PHASE_TOOLS.items():
        assert "free_exec_attacker" not in tools, phase

    # And neither free_exec verb takes a vm_id, which is what removed the role
    # check: the role is the verb and the machine comes from the job.
    for verb in ("free_exec_target", "free_exec_attacker"):
        assert VERB_PARAMS[verb] == {"job_id", "command", "timeout_s"}, verb
