"""The tool layer: the boundary between a model and the broker (ADR 0004).

The broker trusts one unprivileged caller, identified by SO_PEERCRED. A model
has no identity it could present and never will, so "the model calls verbs" is
shorthand: the loop runs in this process, and this module translates a tool
call into a broker call after checking it. That makes the checks here the
trust boundary, not a convenience.

Two restrictions, and both must hold. The verb has to be allowed in the
current phase, and the subject is the job's own target VM - taken from state,
never from what the model asked for.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from typing import Any

from xentry import statediff

# What a model may drive while it is building a target. snapshot and restore
# are here deliberately: they are its cheap undo, and a machine repaired by
# hand is a machine whose history nobody knows.
EXPLORE_TOOLS = frozenset(
    {
        # The target's, and only the target's. free_exec_attacker exists in the
        # broker and is in nobody's allowlist yet; it is NOT in NEVER, because a
        # later phase wants it legitimately.
        "free_exec_target",
        "copy_in",
        "copy_out",
        "http_probe",
        "snapshot",
        "restore",
        "reboot",
    }
)
PHASE_TOOLS: dict[str, frozenset[str]] = {"explore": EXPLORE_TOOLS}

# NEVER, IN ANY PHASE. place_nonce is first because a model that could place
# or read the nonce would make every verdict in this system worthless; the
# rest are the phase and lifecycle, which stay code-owned. `exec` is here too:
# a registered step is the runner's to invoke, and the generated script reaches
# it through the verification path rather than through a model's tool call.
NEVER = frozenset(
    {
        "place_nonce",
        "exec",
        "lock_network",
        "create_network",
        "create_target",
        "create_attacker",
        "destroy_vm",
        "destroy_network",
        "stage_artifact",
        "proxy_capture",
        "read_host_evidence",
    }
)


class ToolRefused(RuntimeError):
    """A tool call the layer will not make, with the reason the model sees."""


@dataclass
class ToolLayer:
    """One job's mediated access to the broker, for one phase at a time."""

    call_broker: Callable[[str, dict[str, Any]], dict[str, Any]]
    job_id: str
    target_vm_id: str
    phase: str = "explore"
    record: Callable[[str, dict[str, Any]], None] | None = None
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def call(self, verb: str, params: dict[str, Any]) -> dict[str, Any]:
        allowed = PHASE_TOOLS.get(self.phase, frozenset())
        if verb in NEVER or verb not in allowed:
            # Named in the refusal, because a model that cannot tell "not in
            # this phase" from "never" will keep trying one of them.
            raise ToolRefused(
                f"{verb} is not a tool"
                + (" at all" if verb in NEVER else f" in the {self.phase} phase")
                + f"; you have {sorted(allowed)}"
            )
        # THE SUBJECT IS NOT THE MODEL'S TO CHOOSE. The free_exec verbs name
        # their role and take a job rather than a VM, so the broker resolves
        # the machine itself and has no role check to get wrong. Every other
        # tool still addresses a VM, and that id is substituted here - so a
        # call naming the attacker reaches the target or nothing.
        if verb.startswith("free_exec_"):
            sent = {**params, "job_id": self.job_id}
        else:
            sent = {**params, "vm_id": self.target_vm_id}
        self.calls.append((verb, sent))
        if self.record is not None:
            self.record(verb, sent)
        return self.call_broker(verb, sent)


# ---------------------------------------------------------------- phase C ---
# The verification, which is where the whole mode's weight sits (ADR 0003).
# Nothing a model did by hand matters to the outcome: the machine that gets
# measured is reverted to the snapshot taken before it touched anything, built
# by its digest-checked script, and compared against the state it explored.
#
# Expressed over callables rather than over an SSH transport or a broker
# client, so it is testable with fakes and so this module keeps importing
# nothing that can reach a machine.

CAPTURE_COMMANDS = {
    "packages": "dpkg-query -W -f '${Package} ${Version}\\n' 2>/dev/null",
    "ports": "ss -Hltn 2>/dev/null | awk '{print $4}' | sed 's/.*://'",
    "units": "systemctl list-unit-files --state=enabled --no-legend 2>/dev/null"
    " | awk '{print $1}'",
}


def capture(run: Callable[[str], str], files: tuple[str, ...] = ()) -> dict[str, Any]:
    """The four sections statediff compares, read off one machine.

    `files` are the paths the model declared it changed; they are hashed
    rather than read, because the comparison only has to answer whether the
    script produced the same bytes - and a config may hold a credential.
    """
    out: dict[str, Any] = {}
    rows = run(CAPTURE_COMMANDS["packages"]).split("\n")
    out["packages"] = dict(
        line.split(" ", 1) for line in rows if line.count(" ") == 1 and line[:1].strip()
    )
    out["ports"] = sorted({int(p) for p in run(CAPTURE_COMMANDS["ports"]).split() if p.isdigit()})
    out["units"] = sorted(u for u in run(CAPTURE_COMMANDS["units"]).split() if u.endswith(".service"))
    if files:
        hashes = run("sha256sum " + " ".join(files) + " 2>/dev/null")
        out["files"] = {
            parts[1]: parts[0]
            for parts in (line.split() for line in hashes.split("\n"))
            if len(parts) == 2
        }
    return out


@dataclass
class Verification:
    """Why the rebuilt machine was accepted or refused, in the model's words."""

    passed: bool
    reason_code: str
    detail: str


def verify(
    revert: Callable[[], None], run_script: Callable[[], dict[str, Any]],
    run: Callable[[str], str], readiness: Callable[[], dict[str, Any]],
    reference: dict[str, Any], files: tuple[str, ...] = (),
) -> Verification:
    """Revert, run only the script, compare, then let readiness decide.

    The order is the argument. Comparing BEFORE readiness means a script that
    produced a different machine is reported as a divergence a model can act
    on, rather than as whatever readiness happens to notice first - and a
    script that passed readiness while diverging would be the worst outcome
    available, since it certifies a machine nobody built on purpose.
    """
    # DECLARED PATHS MUST BE IN BOTH CAPTURES OR IN NEITHER. The reference is
    # taken during exploration, at a different moment and by a different call,
    # so a caller can pass `files` here and have forgotten it there - and then
    # the hand-placed-file check, the one ADR 0003 names as the test to write
    # first, silently asserts nothing and the rebuild is "verified". Found by
    # that very test, which passed against a reference captured without them.
    if files and "files" not in reference:
        return Verification(
            False,
            "reference_incomplete",
            f"declared {len(files)} path(s) but the reference captured none",
        )
    revert()
    result = run_script()
    if int(result.get("exit_code", 1)) != 0:
        return Verification(False, "script_failed", str(result.get("stderr") or "")[:4000])
    diff = statediff.compare(reference, capture(run, files))
    if not diff.matches:
        return Verification(False, "state_diverged", statediff.render(diff))
    ready = readiness()
    if int(ready.get("exit_code", 1)) != 0:
        detail = f"{ready.get('stdout') or ''}\n{ready.get('stderr') or ''}".strip()
        return Verification(False, "readiness_failed", detail[:4000])
    return Verification(True, "verified", statediff.render(diff))


# ------------------------------------------------------------- the session ---
# The model has no API, so everything it asks of the runner arrives as a
# sentinel line in its text (ADR 0003 section 7). This is the state machine
# that reads them and decides when the phase ends - over callables, so it is
# testable without a model and so the model client stays replaceable.

SENTINELS = ("XENTRY_READY", "XENTRY_GIVE_UP", "XENTRY_ADVISORY_REQUEST")


# Brace-counted rather than regex-matched: the prompt's own examples nest
# objects inside `added_assertions`, and a greedy or lazy pattern gets one of
# those two cases wrong. A sentinel whose JSON will not parse yields an empty
# payload rather than None - the model said it was done, and losing that
# because it mis-typed a brace would restart a loop that had finished.
def declaration(text: str) -> tuple[str, dict[str, Any]] | None:
    """The sentinel in a reply, with the JSON object that follows it."""
    for name in SENTINELS:
        if name not in text:
            continue
        tail = text.split(name, 1)[1].lstrip()
        depth = 0
        for index, char in enumerate(tail):
            depth += (char == "{") - (char == "}")
            if depth == 0 and char == "}":
                try:
                    return name, json.loads(tail[: index + 1])
                except ValueError:
                    return name, {}
        return name, {}
    return None


# How the provisioning phase ended, and what it owes the record.
@dataclass
class Session:
    outcome: str
    reason_code: str = ""
    detail: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    readiness_calls: int = 0


# Only a readiness run costs budget. The model's own checks are free by design
# - the prompt says so - because a revert-and-rebuild is minutes, and a loop
# that paid that for every guess could not iterate at all.
def run_session(
    respond: Callable[[str], str], check_ready: Callable[[dict[str, Any]], Verification],
    advisory: Callable[[], str], max_readiness: int = 3, max_turns: int = 40,
) -> Session:
    """Drive the phase until the model is done, gives up, or runs out."""
    used = 0
    feedback = ""
    for _ in range(max_turns):
        found = declaration(respond(feedback))
        feedback = ""
        if found is None:
            continue
        name, payload = found
        if name == "XENTRY_GIVE_UP":
            return Session("gave_up", str(payload.get("reason_code") or "unspecified"),
                           str(payload.get("summary") or ""), payload, used)
        if name == "XENTRY_ADVISORY_REQUEST":
            # The gate from ADR 0003: after a readiness run, never before one.
            feedback = advisory() if used else "the advisory comes after a readiness run"
            continue
        if used >= max_readiness:
            return Session("exhausted", "budget_exhausted", f"{used} used", payload, used)
        used += 1
        result = check_ready(payload)
        if result.passed:
            return Session("ready", "verified", result.detail, payload, used)
        feedback = result.detail
    return Session("exhausted", "budget_exhausted", "no declaration", {}, used)


# -------------------------------------------------------------- the prompt ---
# The extractor's two disjoint fact sets (ADR 0003). The provisioner receives
# these keys and no others, enforced here rather than by whoever calls it: a
# provisioner that has read the exploit can build an environment shaped to make
# that exploit pass - run the service as root, turn off a default, pick the one
# version the exploit likes - and that is teaching to the test. Withholding the
# PoC removes the ability rather than discouraging it, so the filter belongs
# where it cannot be forgotten.
ENVIRONMENT_FACTS = (
    "cve_id",
    "product",
    "affected_range",
    "version_evidence",
    "protocol",
    "ports",
    "auth_required",
    "build_strategy",
    "setup_packages",
    "setup_units",
    "app_dir",
    "fixed_versions",
    "dockerfile",
)

PROMPT_PATH = Path(__file__).with_name("prompts") / "provisioner.txt"


def environment_only(facts: Any) -> dict[str, Any]:
    """The subset of extracted facts a provisioner is allowed to see."""
    known = facts if isinstance(facts, dict) else getattr(facts, "__dict__", {})
    return {key: known[key] for key in ENVIRONMENT_FACTS if key in known}


def prompt_for(
    facts: Any, max_readiness: int, token_budget: int = 0, timeout_s: int = 0
) -> str:
    """The provisioner's instruction, with this job's budgets substituted.

    Recorded against the job by the caller, so a prompt change shows up in the
    history rather than being invisible.
    """
    return Template(PROMPT_PATH.read_text(encoding="utf-8")).substitute(
        max_readiness_calls=max_readiness,
        token_budget=token_budget or "not separately bounded",
        provisioning_timeout=f"{timeout_s}s" if timeout_s else "not separately bounded",
        environment_facts=json.dumps(
            environment_only(facts), indent=2, sort_keys=True, default=str
        ),
    )


# ------------------------------------------------------------- the adapter ---
# What supplies run_session's `respond`. ADK is imported inside the function so
# that importing this module - which runner.py does unconditionally - does not
# require it.
#
# ONE GENERIC TOOL rather than seven typed ones. The model names the verb and
# the layer decides whether it may have it, which is where the allowlist
# already lives; seven wrappers would restate the same set in a second place
# and cost four times the lines to do it.
#
# The loop is created once and reused. InMemoryRunner holds the session, so
# asyncio.run() per turn would start a fresh loop against a session service
# bound to the old one - which is the design question that made this worth
# writing carefully rather than quickly.
def provisioner(
    prompt: str, call: Callable[[str, dict[str, Any]], dict[str, Any]], model: str = ""
) -> Callable[[str], str]:
    """An ADK agent with the broker behind one tool, as a turn-taking callable."""
    import asyncio
    import os
    import uuid

    from google.adk.agents import LlmAgent
    from google.adk.models.lite_llm import LiteLlm
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    def broker(verb: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run one xentry verb against this job's target VM.

        verb is one of the tools named in your instructions. params are that
        verb's own parameters; the job and the machine are supplied for you.
        A refusal comes back as {"refused": ...} and is an answer, not a fault.
        """
        try:
            return call(verb, params)
        except (ToolRefused, RuntimeError) as exc:
            return {"refused": str(exc)}

    agent = LlmAgent(
        name="xentry_provisioner",
        model=LiteLlm(
            model=model
            or os.environ.get("XENTRY_PROVISIONER_MODEL", "deepseek/deepseek-chat")
        ),
        instruction=prompt,
        tools=[broker],
    )
    runner = InMemoryRunner(agent=agent, app_name="xentry")
    loop = asyncio.new_event_loop()
    session_id = uuid.uuid4().hex
    loop.run_until_complete(
        runner.session_service.create_session(
            app_name="xentry", user_id="xentry", session_id=session_id
        )
    )

    async def turn(text: str) -> str:
        said: list[str] = []
        async for event in runner.run_async(
            user_id="xentry",
            session_id=session_id,
            new_message=types.Content(role="user", parts=[types.Part(text=text)]),
        ):
            parts = getattr(getattr(event, "content", None), "parts", None) or []
            # Thought parts are skipped: a reasoning model puts its reasoning in
            # parts[0], which is how the extractor once read the thinking as the
            # answer and reported "invalid JSON" for a reply that was fine.
            said.extend(
                part.text
                for part in parts
                if getattr(part, "text", None) and not getattr(part, "thought", False)
            )
        return "\n".join(said)

    return lambda feedback: loop.run_until_complete(turn(feedback or "continue"))
