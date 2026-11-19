"""The verification is the whole mode's load-bearing wall, so test it there.

ADR 0003 names the test to write first: place a marker by hand during
exploration, then assert it is absent from the verified machine. That is the
test which catches the design collapsing into "the model set up a VM and then
vouched for it", and it is the first one here.
"""

from __future__ import annotations

from typing import Any

from xentry.harness import CAPTURE_COMMANDS, capture, verify


def _machine(
    packages: dict[str, str] | None = None,
    ports: tuple[int, ...] = (),
    units: tuple[str, ...] = (),
    files: dict[str, str] | None = None,
) -> Any:
    """A `run` callable answering the capture commands for a made-up machine."""

    def run(command: str) -> str:
        if command == CAPTURE_COMMANDS["packages"]:
            return "\n".join(f"{n} {v}" for n, v in (packages or {}).items())
        if command == CAPTURE_COMMANDS["ports"]:
            return "\n".join(str(p) for p in ports)
        if command == CAPTURE_COMMANDS["units"]:
            return "\n".join(units)
        if command.startswith("sha256sum "):
            return "\n".join(f"{digest}  {path}" for path, digest in (files or {}).items())
        raise AssertionError(f"unexpected command: {command}")

    return run


OK = {"exit_code": 0, "stdout": "", "stderr": ""}


def test_a_hand_placed_file_fails_verification() -> None:
    """THE test. A marker created during exploration must not survive.

    The commonest way a good session produces a failing script is a config the
    model wrote by hand and never put in the script. If verification passed
    anyway, every later measurement would run on a machine whose state nobody
    can reproduce - and the mode's entire premise, that the rebuild is the
    proof, would be decoration.

    Here the reference carries /etc/app.conf because the model wrote it during
    exploration; the script does not, so the rebuilt machine lacks it.
    """
    reference = capture(
        _machine({"app": "1.0"}, (80,), ("app.service",), {"/etc/app.conf": "a" * 64}),
        files=("/etc/app.conf",),
    )
    rebuilt = _machine({"app": "1.0"}, (80,), ("app.service",), {})
    readiness_calls: list[int] = []

    result = verify(
        revert=lambda: None,
        run_script=lambda: OK,
        run=rebuilt,
        readiness=lambda: (readiness_calls.append(1), OK)[1],
        reference=reference,
        files=("/etc/app.conf",),
    )

    assert result.passed is False
    assert result.reason_code == "state_diverged"
    # The model has to be able to act on it, so the path is named.
    assert "/etc/app.conf" in result.detail
    # And readiness was never reached: a diverged machine is not a candidate.
    assert readiness_calls == []


def test_a_version_drift_fails_before_readiness_can_pass_it() -> None:
    """Readiness asserts a prefix; a drift inside that prefix would pass it.

    redis 5.0.14-1+deb10u2 and -u3 both satisfy a prefix check, so readiness
    alone cannot tell the machine the model explored from the one its script
    built. The comparison runs first for exactly this reason, and a readiness
    that would have said yes is never asked.
    """
    reference = capture(_machine({"redis-server": "5:5.0.14-1+deb10u2"}, (6379,)))
    rebuilt = _machine({"redis-server": "5:5.0.14-1+deb10u3"}, (6379,))
    asked: list[int] = []

    result = verify(
        revert=lambda: None,
        run_script=lambda: OK,
        run=rebuilt,
        readiness=lambda: (asked.append(1), OK)[1],
        reference=reference,
        files=(),
    )
    assert result.reason_code == "state_diverged"
    assert "deb10u2" in result.detail and "deb10u3" in result.detail
    assert asked == [], "readiness was asked about a machine already known to differ"


def test_the_revert_happens_before_the_script_runs() -> None:
    """Otherwise the script is tested against the machine it already built.

    A script run on the exploratory VM would pass whatever the model did by
    hand, which is the failure this whole phase exists to prevent.
    """
    order: list[str] = []
    state = _machine({"app": "1.0"})
    verify(
        revert=lambda: order.append("revert"),
        run_script=lambda: (order.append("script"), OK)[1],
        run=state,
        readiness=lambda: (order.append("readiness"), OK)[1],
        reference=capture(state),
        files=(),
    )
    assert order == ["revert", "script", "readiness"]


def test_a_failing_script_is_reported_as_itself() -> None:
    """Not as a divergence, and not as a readiness failure.

    The three reason codes are the three different things a reader has to do
    next, so conflating them costs a debugging cycle every time.
    """
    result = verify(
        revert=lambda: None,
        run_script=lambda: {"exit_code": 1, "stdout": "", "stderr": "E: no package apache9"},
        run=_machine(),
        readiness=lambda: OK,
        reference={},
        files=(),
    )
    assert result.passed is False
    assert result.reason_code == "script_failed"
    assert "apache9" in result.detail


def test_readiness_still_decides_when_the_state_matches() -> None:
    """The comparison is a gate before readiness, never a substitute for it.

    A script can rebuild the explored state exactly and still not produce an
    affected, listening service - that is readiness's question, and it keeps
    the last word.
    """
    state = _machine({"app": "1.0"}, (80,))
    result = verify(
        revert=lambda: None,
        run_script=lambda: OK,
        run=state,
        readiness=lambda: {"exit_code": 1, "stdout": "port 80 never listened", "stderr": ""},
        reference=capture(state),
        files=(),
    )
    assert result.reason_code == "readiness_failed"
    assert "never listened" in result.detail


def test_a_clean_rebuild_passes_and_says_what_it_compared() -> None:
    """A pass has to be auditable too, not just a boolean.

    The detail carries the comparison either way, so a reader of a job that
    passed can see what was actually held equal rather than taking it on
    trust.
    """
    state = _machine({"app": "1.0"}, (80,), ("app.service",))
    result = verify(
        revert=lambda: None,
        run_script=lambda: OK,
        run=state,
        readiness=lambda: OK,
        reference=capture(state),
        files=(),
    )
    assert result.passed is True
    assert result.reason_code == "verified"
    assert result.detail


def test_an_extra_dependency_does_not_fail_a_rebuild() -> None:
    """A script may legitimately pull a package the model did not install.

    apt resolves a closure, so insisting on an exact package set would refuse
    correct scripts. Extras are reported and never decisive - that choice
    lives in statediff, and this pins it at the level that matters.
    """
    reference = capture(_machine({"app": "1.0"}, (80,)))
    rebuilt = _machine({"app": "1.0", "libfoo1": "2.3"}, (80,))
    result = verify(
        revert=lambda: None,
        run_script=lambda: OK,
        run=rebuilt,
        readiness=lambda: OK,
        reference=reference,
        files=(),
    )
    assert result.passed is True, result.detail


def test_declared_paths_missing_from_the_reference_are_refused() -> None:
    """A forgotten argument must not silence the check it belongs to.

    The reference capture happens during exploration; the rebuilt one happens
    here. Pass `files` to the second and forget it in the first, and the
    hand-placed-file check - the test ADR 0003 names first - asserts nothing
    while reporting "verified". That is how it behaved until this guard, and
    the marker test above is what exposed it.

    Refusing is right rather than inferring: the reference is already taken,
    so there is nothing to recover, and a run that cannot make the comparison
    it was asked for should say so.
    """
    state = _machine({"app": "1.0"}, (80,))
    result = verify(
        revert=lambda: None,
        run_script=lambda: OK,
        run=state,
        readiness=lambda: OK,
        reference=capture(state),  # captured WITHOUT files
        files=("/etc/app.conf",),  # but a path is declared here
    )
    assert result.passed is False
    assert result.reason_code == "reference_incomplete"
    assert "1 path" in result.detail
