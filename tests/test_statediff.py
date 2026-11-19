"""The state comparison that decides a harness job, tested with dicts alone.

ADR 0003 makes the exploratory VM the reference state, because "the script ran
without error" is too weak a test. Four of the failures below are silent, which
is why they are each their own test:

  - a version drift reported as a match. The script installed the package, the
    rebuild "worked", and the reproduction is of a different build. This is the
    commonest real failure and the one the whole module exists for.
  - a hand-placed file never written down. ADR 0003 names it the commonest way
    a good session produces a failing script, and the only trace is a digest.
  - a partial capture raising instead of reporting. A capture is produced by
    commands that can fail; an exception loses every finding in the run, so a
    half-read machine must still compare.
  - an extra package failing the comparison. A script may legitimately pull a
    dependency the model never installed by hand, so an extra must be reported
    and must NOT fail the rebuild - otherwise the gate is unusable.

The rendering is tested on substrings rather than on whole lines: it goes back
to the model verbatim, and what matters is that the name, the old value and the
new value are all in it. A count would pass a test that asserted a count.
"""

from __future__ import annotations

import ast
from pathlib import Path

from xentry.statediff import SECTIONS, Capture, Comparison, Divergence, compare, render

DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
CONF = "/etc/redis/redis.conf"


def _full() -> Capture:
    return {
        "packages": {"redis-server": "5:5.0.14-1+deb10u2", "libc6": "2.28-10"},
        "ports": [6379, 80],
        "units": ["redis-server"],
        "files": {CONF: DIGEST},
    }


def _kinds(result: Comparison) -> list[str]:
    return [d.kind for d in result.divergences]


def _only(result: Comparison) -> Divergence:
    assert len(result.divergences) == 1, _kinds(result)
    return result.divergences[0]


# ----------------------------------------------------------- the match ---


def test_identical_captures_match() -> None:
    """A rebuild that reproduced the state must not be failed by its own comparison."""
    result = compare(_full(), _full())
    assert result.matches
    assert result.divergences == ()
    assert "rebuilds the state you explored" in render(result)


def test_empty_captures_match() -> None:
    """Two captures that asserted nothing are not a divergence - they are no evidence.

    The caller decides whether an empty reference is acceptable; this module
    must not invent a failure out of two empty dicts, and must not raise.
    """
    result = compare({}, {})
    assert result.matches
    assert result.divergences == ()


def test_section_order_and_names_are_sorted() -> None:
    """Set iteration order must never reach the model: the output is recorded and diffed.

    `compare` walks a union of two sets of names, which is exactly where an
    unstable order creeps in. Two runs over the same captures that print the
    divergences in a different order make a stored comparison undiffable.
    """
    reference = _full()
    rebuilt: Capture = {"packages": {}, "ports": [], "units": [], "files": {}}
    first = compare(reference, rebuilt)
    assert _kinds(first) == [
        "package_missing",  # libc6 before redis-server: sorted within the section
        "package_missing",
        "file_missing",
        "port_missing",
        "port_missing",
        "unit_missing",
    ]
    assert [d.subject for d in first.divergences[:2]] == ["libc6", "redis-server"]
    assert [d.subject for d in first.divergences[3:5]] == ["6379", "80"]
    assert compare(reference, rebuilt) == first
    assert render(compare(reference, rebuilt)) == render(first)


# ------------------------------------------------- each divergence class ---


def test_package_absent_is_classified_as_missing() -> None:
    """A package the script forgot to install, which is its own class of mistake."""
    rebuilt = _full()
    del rebuilt["packages"]["libc6"]
    found = _only(compare(_full(), rebuilt))
    assert found.kind == "package_missing"
    assert found.subject == "libc6"
    assert found.expected == "2.28-10"
    assert found.actual == "not installed"


def test_package_version_drift_is_its_own_class() -> None:
    """The silent failure: installed, so the script "worked", but a different build.

    Classifying this as a missing package would be wrong in the other
    direction too - the model's fix is a version pin, not an install line.
    """
    rebuilt = _full()
    rebuilt["packages"]["redis-server"] = "5:5.0.14-1+deb10u3"
    found = _only(compare(_full(), rebuilt))
    assert found.kind == "package_drift"
    assert found.expected == "5:5.0.14-1+deb10u2"
    assert found.actual == "5:5.0.14-1+deb10u3"
    assert not compare(_full(), rebuilt).matches


def test_port_not_listening() -> None:
    """A service that did not come up. The state word is printed, not just "absent"."""
    rebuilt = _full()
    rebuilt["ports"] = [6379]
    found = _only(compare(_full(), rebuilt))
    assert found.kind == "port_missing"
    assert found.subject == "80"
    assert (found.expected, found.actual) == ("listening", "not listening")


def test_unit_not_enabled() -> None:
    """A unit that works now and will not survive the boot the PoC run may include."""
    rebuilt = _full()
    rebuilt["units"] = []
    found = _only(compare(_full(), rebuilt))
    assert found.kind == "unit_missing"
    assert (found.expected, found.actual) == ("enabled", "not enabled")


def test_file_digest_drift() -> None:
    """A config the script writes differently from the one the model wrote by hand."""
    rebuilt = _full()
    rebuilt["files"][CONF] = OTHER_DIGEST
    found = _only(compare(_full(), rebuilt))
    assert found.kind == "file_drift"
    assert found.subject == CONF
    assert (found.expected, found.actual) == (DIGEST, OTHER_DIGEST)


def test_file_missing_entirely() -> None:
    """The hand-placed file nobody wrote down - ADR 0003's named failure mode."""
    rebuilt = _full()
    rebuilt["files"] = {}
    found = _only(compare(_full(), rebuilt))
    assert found.kind == "file_missing"
    assert found.subject == CONF
    assert found.actual == "not present"


def test_every_class_in_one_comparison() -> None:
    """All six classes are reachable at once; none shadows another."""
    rebuilt: Capture = {
        "packages": {"redis-server": "5:5.0.14-1+deb10u3", "libjemalloc2": "5.2.1-1"},
        "ports": [6379],
        "units": [],
        "files": {CONF: OTHER_DIGEST},
    }
    kinds = set(_kinds(compare(_full(), rebuilt)))
    assert kinds == {
        "package_missing",
        "package_drift",
        "package_extra",
        "file_drift",
        "port_missing",
        "unit_missing",
    }


# ------------------------------------------------- extras are the weak kind ---


def test_extra_package_is_reported_but_does_not_fail_the_rebuild() -> None:
    """An extra dependency is a finding, not a failure, or the gate is unusable.

    `apt` pulls recommends the model never typed. If that failed the rebuild,
    no script would ever pass and the mode would be dead on arrival.
    """
    rebuilt = _full()
    rebuilt["packages"]["libjemalloc2"] = "5.2.1-1"
    result = compare(_full(), rebuilt)
    found = _only(result)
    assert found.kind == "package_extra"
    assert (found.expected, found.actual) == ("not installed", "5.2.1-1")
    assert result.matches, "an extra dependency must not fail the rebuild"


def test_extras_in_every_section_are_weak() -> None:
    """A port, unit or file only on the rebuilt machine is weak for the same reason."""
    rebuilt = _full()
    rebuilt["ports"].append(9000)
    rebuilt["units"].append("rsyslog")
    rebuilt["files"]["/etc/motd"] = DIGEST
    result = compare(_full(), rebuilt)
    assert _kinds(result) == ["file_extra", "port_extra", "unit_extra"]
    assert result.matches


def test_one_hard_divergence_beside_extras_still_fails() -> None:
    """Extras must not dilute a real failure: weakness is per class, not a score."""
    rebuilt = _full()
    rebuilt["packages"]["libjemalloc2"] = "5.2.1-1"
    rebuilt["ports"] = [6379]
    result = compare(_full(), rebuilt)
    assert set(_kinds(result)) == {"package_extra", "port_missing"}
    assert not result.matches


# --------------------------------------------------------- partial captures ---


def test_missing_key_in_either_capture_does_not_raise() -> None:
    """A command that failed leaves a key out; an exception would lose the whole run."""
    for partial in ({}, {"packages": {}}, {"ports": [80]}, {"units": [], "files": {}}):
        assert isinstance(compare(partial, _full()), Comparison)
        assert isinstance(compare(_full(), partial), Comparison)
        assert isinstance(render(compare(partial, _full())), str)


def test_a_none_section_is_read_as_empty() -> None:
    """`{"ports": None}` is what a parser hands over when a command printed nothing."""
    result = compare({"ports": None, "packages": None}, _full())
    # None and an absent key both assert nothing, so everything on the rebuilt
    # side is an extra - including the sections the reference never mentioned.
    assert _kinds(result) == [
        "package_extra",
        "package_extra",
        "file_extra",
        "port_extra",
        "port_extra",
        "unit_extra",
    ]
    assert result.matches


def test_unreadable_rebuilt_section_fails_closed() -> None:
    """A section the rebuild could not read must not pass as if it had been checked.

    This is the deliberate asymmetry: if `ss` failed on the rebuilt machine we
    do not know the ports listen, and reporting them as listening would let a
    broken capture certify a broken rebuild. Reported as closed, the model sees
    a divergence and runs readiness again.
    """
    result = compare(_full(), {"packages": _full()["packages"], "files": _full()["files"]})
    assert _kinds(result) == ["port_missing", "port_missing", "unit_missing"]
    assert not result.matches


def test_unreadable_reference_section_asserts_nothing() -> None:
    """The other direction stays silent: a reference that saw no units requires none."""
    reference = _full()
    del reference["units"]
    rebuilt = _full()
    rebuilt["units"] = []
    result = compare(reference, rebuilt)
    assert result.divergences == ()
    assert result.matches


def test_non_string_values_are_coerced_not_rejected() -> None:
    """Ports arrive as ints and a version may arrive as a float from a loose parser."""
    result = compare({"ports": [6379, 80], "packages": {"foo": 1}}, {"ports": ["6379"]})
    assert _kinds(result) == ["package_missing", "port_missing"]
    assert result.divergences[0].expected == "1"
    assert result.divergences[1].subject == "80"


# ------------------------------------------------------------- the rendering ---


def test_rendering_names_the_package_and_both_versions() -> None:
    """The output goes to the model verbatim, so a count is not an actionable report.

    This is the test that would catch "3 divergences" being all the model gets:
    it cannot fix a version drift it cannot see the versions of.
    """
    rebuilt = _full()
    rebuilt["packages"]["redis-server"] = "5:5.0.14-1+deb10u3"
    text = render(compare(_full(), rebuilt))
    assert "package_drift" in text
    assert "redis-server" in text
    assert "5:5.0.14-1+deb10u2" in text
    assert "5:5.0.14-1+deb10u3" in text
    assert "does not rebuild" in text


def test_rendering_names_the_port_the_unit_and_the_path() -> None:
    """Every class names its own subject; no class renders as a bare class name."""
    rebuilt: Capture = {"packages": _full()["packages"]}
    text = render(compare(_full(), rebuilt))
    assert "80" in text
    assert "6379" in text
    assert "redis-server was enabled" in text
    assert CONF in text
    assert DIGEST in text


def test_rendering_separates_hard_from_weak_counts() -> None:
    """The model has to know which findings it must fix and which it may ignore."""
    rebuilt = _full()
    rebuilt["packages"]["libjemalloc2"] = "5.2.1-1"
    rebuilt["ports"] = [6379]
    text = render(compare(_full(), rebuilt))
    assert "1 divergence(s) that invalidate the reproduction" in text
    assert "1 weaker one(s)" in text
    assert text.count("\n") == 2, "one head line and one line per divergence"


def test_rendering_a_match_ends_without_a_colon() -> None:
    """A trailing colon with nothing after it reads as truncated output to a model."""
    text = render(compare(_full(), _full()))
    assert text.endswith(".")
    assert "\n" not in text


# -------------------------------------------------------------- purity ---


def test_compare_does_not_mutate_its_inputs() -> None:
    """The caller keeps the captures for the job record; normalising in place corrupts it."""
    reference, rebuilt = _full(), _full()
    rebuilt["ports"] = [6379]
    before = (repr(reference), repr(rebuilt))
    compare(reference, rebuilt)
    assert (repr(reference), repr(rebuilt)) == before


def test_module_imports_nothing_that_could_do_io() -> None:
    """Purity is the property that makes this testable with dicts; a test keeps it.

    An import of os, subprocess, pathlib or socket here would mean the
    comparison could read the machine it is comparing, and the gate would stop
    being reproducible from a stored capture.
    """
    source = Path(__file__).resolve().parents[1] / "src" / "xentry" / "statediff.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imported = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    assert imported == {"__future__", "typing"}, imported


def test_section_keys_are_the_documented_capture_shape() -> None:
    """The shape is the contract with whoever runs the commands; it must stay narrow."""
    assert set(SECTIONS) == {"packages", "ports", "units", "files"}
    assert [key[:-1] for key in SECTIONS] == ["package", "file", "port", "unit"]
