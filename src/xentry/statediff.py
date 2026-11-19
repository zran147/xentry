"""ADR 0003's state comparison: is the machine the script built the one explored?"""

# Captures in, classified divergences out, and no I/O at all - the thing that
# decides whether a harness job's script rebuilt the environment is testable
# with nothing but dicts.

from __future__ import annotations

from typing import Any, NamedTuple

# A capture is a plain dict, produced by whoever can run commands on a machine;
# this module never runs one. Four optional keys, and nothing else is read:
#
#   {"packages": {"redis-server": "5:5.0.14-1+deb10u2"},  name -> version
#    "ports":    [6379, 80],                              listening tcp
#    "units":    ["redis-server"],                         enabled units
#    "files":    {"/etc/redis/redis.conf": "<sha256>"}}   declared path -> sha256
#
# Every key is optional because a capture may be partial: the command that would
# have filled it can fail, and a comparison that raises on a half-read machine
# tells the model nothing. An absent section on the REBUILT side is therefore
# read as "nothing found", not as "nothing asserted" - a comparison that cannot
# see the ports must not report that they listen. The other direction is silent
# by construction: a reference that captured no units asserts nothing about
# units, so an unreadable reference weakens the test instead of failing it.
Capture = dict[str, Any]

# key -> the state its membership asserts. `packages` and `files` carry a value
# per name (a version, a digest), so the state word is only ever used for its
# negation; `ports` and `units` are bare lists, so membership IS the value and
# the word is what a divergence prints.
SECTIONS = {"packages": "installed", "files": "present", "ports": "listening", "units": "enabled"}


# `<noun>_<missing|drift|extra>` plus both sides of the difference. The classes
# mean different things, which is the whole point of classifying rather than
# counting. `package_missing` is a line the script forgot. `package_drift` is a
# different version - the commonest real failure, and the one that silently
# invalidates a reproduction. `file_drift` and `file_missing` are usually the
# config the model wrote by hand during exploration and never put in the script.
# `port_missing` is a service that did not come up, `unit_missing` one that will
# not survive a boot. Anything ending `_extra` is only on the rebuilt machine and
# is deliberately weaker: a script may legitimately pull in an extra dependency,
# so extras are reported and do not fail the comparison.
class Divergence(NamedTuple):
    kind: str
    subject: str
    expected: str
    actual: str


class Comparison(NamedTuple):
    matches: bool
    divergences: tuple[Divergence, ...]


def _as_map(section: Any, state: str) -> dict[str, str]:
    return ({str(k): str(v) for k, v in section.items()} if isinstance(section, dict)
            else {str(item): state for item in section or ()})


# The reference is the exploratory VM, which ADR 0003 makes the state a rebuild
# has to match; `rebuilt` is the machine the script produced from a clean
# snapshot. Order is stable - sections as declared, names sorted - because this
# goes into a job record and is diffed between runs.
def compare(reference: Capture, rebuilt: Capture) -> Comparison:
    """Every way the rebuilt capture departs from the reference one, classified."""
    out: list[Divergence] = []
    for key, state in SECTIONS.items():
        noun, want = key[:-1], _as_map(reference.get(key), state)
        got = _as_map(rebuilt.get(key), state)
        for name in sorted(want.keys() | got.keys()):
            was, now = want.get(name, f"not {state}"), got.get(name, f"not {state}")
            if was != now:
                kind = "_extra" if name not in want else "_missing" if name not in got else "_drift"
                out.append(Divergence(noun + kind, name, was, now))
    return Comparison(all(d.kind.endswith("_extra") for d in out), tuple(out))


def sentence(d: Divergence) -> str:
    return (f"{d.kind}: {d.subject} was {d.expected} on the exploratory VM and is {d.actual} "
            "on the machine your script built")


# ADR 0003 wants readiness output verbose, so that a failure shows "the gap
# between what you intended and what your script did". A count cannot do that:
# every line names the package, version, port or path, says what it was and what
# it became, and gives the class the difference falls in.
def render(result: Comparison) -> str:
    """The comparison as sentences, because this goes back to the model verbatim."""
    hard = sum(not d.kind.endswith("_extra") for d in result.divergences)
    verdict = "rebuilds" if result.matches else "does not rebuild"
    head = (f"your script {verdict} the state you explored: {hard} divergence(s) that invalidate "
            f"the reproduction and {len(result.divergences) - hard} weaker one(s) that an extra "
            "dependency could explain")
    return "\n".join([head + (":" if result.divergences else "."),
                      *(f"  {sentence(d)}" for d in result.divergences)])
