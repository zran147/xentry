"""The session state machine: when the phase ends, and on whose terms.

A model has no API, so every request it makes of the runner arrives as a
sentinel line in its text. These test the reading of those lines and the
budget that bounds the loop - over fakes, because the decision logic is the
part that must be right before a model is ever given tools.
"""

from __future__ import annotations

from typing import Any

from xentry.harness import Session, Verification, declaration, run_session

PASS = Verification(True, "verified", "state matched")
FAIL = Verification(False, "state_diverged", "package_missing: libfoo")


class Model:
    """Replies in order, and records what it was told between turns."""

    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.heard: list[str] = []

    def __call__(self, feedback: str) -> str:
        self.heard.append(feedback)
        return self.replies.pop(0) if self.replies else "still working"


def _run(model: Model, check: Any = lambda p: PASS, **kw: Any) -> Session:
    return run_session(model, check, lambda: "THE ADVISORY", **kw)


def test_a_give_up_is_a_result_with_its_reason() -> None:
    """The reason code is the whole value of a failed harness run.

    A job that ends "the mirror carries no affected version" tells a reader
    something about the CVE. One that ends "failed" does not, which is why the
    code is carried out of the payload rather than summarised.
    """
    model = Model(
        'nothing here works\nXENTRY_GIVE_UP\n{"reason_code": "version_unavailable",'
        ' "summary": "no affected redis in the dated archive"}'
    )
    result = _run(model)
    assert result.outcome == "gave_up"
    assert result.reason_code == "version_unavailable"
    assert "affected redis" in result.detail
    assert result.readiness_calls == 0


def test_a_ready_declaration_that_verifies_ends_the_phase() -> None:
    model = Model('XENTRY_READY\n{"script": "/root/p.sh", "declared_version": null}')
    result = _run(model)
    assert result.outcome == "ready"
    assert result.reason_code == "verified"
    assert result.payload["script"] == "/root/p.sh"
    assert result.readiness_calls == 1


def test_a_failed_verification_is_handed_back_and_costs_a_call() -> None:
    """The output goes back verbatim: it is the only honest feedback it gets.

    ADR 0003 requires readiness be verbose to the model, because the gap
    between what it intended and what its script did is in that output. A loop
    that swallowed the detail would leave it guessing at the same wall.
    """
    model = Model(
        'XENTRY_READY\n{"script": "/root/p.sh"}',
        'XENTRY_READY\n{"script": "/root/p.sh"}',
    )
    tries = iter([FAIL, PASS])
    result = _run(model, check=lambda p: next(tries))
    assert result.outcome == "ready"
    assert result.readiness_calls == 2
    # The failure's detail reached the model before its second attempt.
    assert FAIL.detail in model.heard[1]


def test_the_readiness_budget_is_a_budget() -> None:
    """A revert-and-rebuild is minutes, so an unbounded loop is unbounded cost."""
    model = Model(*['XENTRY_READY\n{"script": "/root/p.sh"}'] * 6)
    result = _run(model, check=lambda p: FAIL, max_readiness=2)
    assert result.outcome == "exhausted"
    assert result.reason_code == "budget_exhausted"
    assert result.readiness_calls == 2, "a third run was paid for"


def test_the_advisory_comes_after_a_readiness_run_and_not_before() -> None:
    """Both halves of ADR 0003's gate, because either alone is useless.

    Without the "after" condition it is a free first move, and a provisioner
    that reads the advisory before trying anything is one that was never
    withheld the exploit detail the advisory quotes.
    """
    early = Model(
        'XENTRY_ADVISORY_REQUEST\n{"question": "which version?"}',
        'XENTRY_GIVE_UP\n{"reason_code": "facts_insufficient"}',
    )
    _run(early)
    assert "after a readiness run" in early.heard[1]
    assert "THE ADVISORY" not in early.heard[1]

    late = Model(
        'XENTRY_READY\n{"script": "/root/p.sh"}',
        'XENTRY_ADVISORY_REQUEST\n{"question": "which version?"}',
        'XENTRY_GIVE_UP\n{"reason_code": "facts_insufficient"}',
    )
    _run(late, check=lambda p: FAIL)
    assert "THE ADVISORY" in late.heard[2]


def test_a_reply_with_no_sentinel_is_the_model_working() -> None:
    """Most turns are tool use. Only a sentinel is a request of the runner."""
    model = Model("let me look at the package list", "and the unit file")
    result = _run(model, max_turns=3)
    assert result.outcome == "exhausted"
    assert result.readiness_calls == 0
    # Nothing was fed back: there was nothing to answer.
    assert model.heard == ["", "", ""]


def test_a_nested_payload_is_read_whole() -> None:
    """added_assertions nests objects, which is where a regex gets it wrong.

    A lazy pattern stops at the first inner brace and a greedy one swallows
    anything after the block, so the parser counts braces instead.
    """
    text = (
        'XENTRY_READY\n{"script": "/root/p.sh", "added_assertions": '
        '[{"port": 8080}, {"version": {"binary": "httpd", "contains": "2.4.49"}}]}'
    )
    found = declaration(text)
    assert found is not None
    name, payload = found
    assert name == "XENTRY_READY"
    assert payload["added_assertions"][1]["version"]["contains"] == "2.4.49"


def test_a_mistyped_payload_does_not_lose_the_declaration() -> None:
    """It said it was done. Restarting a finished loop over a brace is worse.

    The sentinel is returned with an empty payload, so the caller can refuse
    for a missing script rather than silently treating the turn as tool use
    and asking the model to carry on.
    """
    found = declaration('XENTRY_GIVE_UP\n{"reason_code": "facts_insufficient",}')
    assert found is not None
    assert found[0] == "XENTRY_GIVE_UP"
    assert found[1] == {}
    assert declaration("no sentinel anywhere here") is None
