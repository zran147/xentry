"""Does the dated archive carry this package at this version, at this serial?"""

# `release.published_versions` answers what an archive EVER carried - Debian's
# snapshot index is per package across the whole history, Launchpad's is per
# suite across all pockets and all time - and its own docstring defers the
# dated question to readiness: "a version that existed in 2021 is not in a 2024
# serial of sid, and readiness says so."
#
# Readiness cannot always say so. The `by_package` and ceiling-sweep paths
# leave `expected_version` empty on purpose, and there nothing checks the
# version at all; a job then runs the exploit against whatever the serial
# carried and reports that it did not reproduce. Measured over the 26 checks
# admitted on 2026-11-15, ten of the fifteen that named both a serial and a
# package would have failed at provisioning or, worse, provisioned a build
# that was already fixed.
#
# One authority answers it: the Packages index of that suite at that serial. It
# costs a single fetch - 8.8 MB for Debian sid, 1.4 MB for Ubuntu jammy, both
# under a second - against a VM create, a provision and a readiness probe.
#
# Ubuntu needs this most, because there the serial does almost nothing. A
# release pocket is immutable, so `dists/jammy` is served byte-identical at
# every serial, including serials from before that release existed. A release
# that did not exist yet answers with a nine-byte stub rather than an error,
# and `-updates`/`-security` do not exist below mid-2023. So an Ubuntu job
# installs the GA version of anything in main whatever the advisory's date, and
# the only way to learn that is to read the index.

from __future__ import annotations

import lzma
import re

from xentry import release

ROOT = {
    "debian": "https://snapshot.debian.org/archive/debian",
    "ubuntu": "https://snapshot.ubuntu.com/ubuntu",
}
INDEX = "{root}/{serial}/dists/{suite}/{component}/binary-amd64/Packages.xz"
# Debian has no universe and Ubuntu no contrib; the absent one is a miss, not
# an error, so asking for both costs one 404 rather than a branch on the archive.
COMPONENTS = ("main", "universe", "contrib")
# A suite that does not exist at a serial answers 200 with a nine-byte xz of
# nothing. Compressed indexes of real suites are six figures and up.
MIN_INDEX_BYTES = 1024
# sid's main is 8.8 MB compressed; fetch's 2 MB default would truncate it.
MAX_INDEX_BYTES = 32_000_000


def refusal(
    package: str,
    expected: str,
    serial: str,
    suite: str,
    archive: str,
    fetch_fn: object,
    ceiling: tuple[str, bool] | None = None,
    ranges: tuple[tuple[str, str, bool], ...] = (),
) -> str:
    """"" when a job can provision this, else the sentence to refuse with."""
    if not package or not serial or not suite:
        return ""
    # `.+\n` cannot match a blank line, so the scan stops at the end of the
    # stanza it started in and cannot read a neighbour's Version.
    pattern = re.compile(
        rf"^Package: {re.escape(package)}\n(?:.+\n)*?Version: (.+)$", re.MULTILINE
    )
    versions: list[str] = []
    # Separate "no index for this suite at this serial" from "this suite does
    # not carry this package": the first is a serial the archive cannot
    # honour, the second a package it never had.
    any_index = False
    for component in COMPONENTS:
        url = INDEX.format(
            root=ROOT[archive], serial=serial, suite=suite, component=component
        )
        try:
            body = fetch_fn(url, max_bytes=MAX_INDEX_BYTES, timeout=90.0).body  # type: ignore[operator]
            if len(body) < MIN_INDEX_BYTES:
                continue
            any_index = True
            text = lzma.decompress(body).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001,S112 - an absent component is a miss
            continue
        versions.extend(match.group(1).strip() for match in pattern.finditer(text))
        if versions:
            break
    if not any_index:
        # Two causes, and from here they are indistinguishable: a 404 for a
        # component Debian does not have looks like a timeout. Naming the
        # likely one as THE one would read as a verdict on a transient
        # failure, and at sweep volume transient failures are certain.
        return (
            f"{archive} served no readable package index for {suite} at {serial} "
            f"- the serial may predate the release or this archive's snapshots, "
            f"or the archive may not have answered; a retry tells them apart"
        )
    if not versions:
        return f"{archive} {suite} at {serial} does not carry {package}"
    # An epoch is archive bookkeeping, not part of the upstream version an
    # advisory names: jammy's zabbix is 1:5.0.17+dfsg-1 for upstream 5.0.17.
    #
    # The PREFIX alone is not enough, and matching on it alone was a hole with
    # exactly one shape: a fallback prefix like "2.4" is satisfied by 2.4.58,
    # which carries the fix, so this answered "carries it" for a build the CVE
    # does not affect - and that produces a job reporting "did not reproduce"
    # rather than a refusal. resolve() filters its own CHOICE by the ceiling;
    # the dated archive's answer has to be filtered by it too.
    def affected(version: str) -> bool:
        bare = version.split(":", 1)[-1]
        if ranges:
            # A branch per segment, and a floor per branch. upper_bound
            # collapses a multi-segment range to one bound, so redis 7.0.15 -
            # which ">= 7.0.0, < 7.2.6" plainly covers - was compared against
            # the FIRST branch's 6.2.16 and called unaffected. The floors are
            # what keep the gaps out: 6.5 is above 6.2.16 and below 7.0.0.
            return any(
                release.at_least(bare, floor)
                and release.within(bare, top.split(":", 1)[-1], inclusive)
                for floor, top, inclusive in ranges
            )
        if ceiling is not None:
            # The ceiling is the authority, NOT the prefix. candidate.prefix is
            # the search key the resolver matched on, not a claim about the
            # build that installs: "1.30.0 before 1.30.2" yields the prefixes
            # 1.30.2, 1.30 and 1.30.0, and nginx 1.30.1-2 - which the range
            # plainly covers - starts with neither outer one. Requiring the
            # prefix here refused an affected build as unaffected, and which
            # answer you got depended on which prefix matched first.
            #
            # The bound's epoch is stripped for the same reason the version's
            # is: a bound of 5:7.0.15-2 compared against 7.0.15-1build2 parses
            # as version five and rejects everything.
            return release.within(bare, ceiling[0].split(":", 1)[-1], ceiling[1])
        return not expected or bare.startswith(expected) or version.startswith(expected)

    if (expected or ceiling or ranges) and not any(affected(v) for v in versions):
        if ranges:
            branches = "; ".join(f"{low}-{high}" for low, high, _ in ranges)
            return (
                f"{archive} {suite} at {serial} carries {package} {versions[0]}, "
                f"which falls in none of the branches this advisory names "
                f"({branches}) - so that build is not affected by this CVE"
            )
        if ceiling is None:
            return (
                f"{archive} {suite} at {serial} carries {package} {versions[0]}, "
                f"not the {expected} this advisory names"
            )
        edge = "at or below" if ceiling[1] else "below"
        return (
            f"{archive} {suite} at {serial} carries {package} {versions[0]}, which "
            f"is not {edge} {ceiling[0]} - the version this advisory's range ends "
            f"at - so that build is not affected by this CVE"
        )
    return ""
