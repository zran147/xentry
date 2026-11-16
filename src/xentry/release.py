"""Which release of which archive can install the affected version.

The apt snapshot serial moves along one release's timeline; it cannot cross
releases. No serial of noble will ever yield PHP 7.2, because noble never
shipped it. So a derived target has to choose a release as well as a serial,
and that choice decides what the job installs.

It is a lookup, not a guess. Launchpad publishes, per release, every binary
version the archive ever carried, so "can bionic install php7.2-cli 7.2.10?"
is answered by one small query before anything is built - rather than by a
model, whose wrong answer would cost a 2.5 GB image build and surface as an
indistinguishable provision failure.

Only releases whose image is built and pinned are considered: resolving to one
that cannot boot would turn a clean refusal into a late, confusing failure.

Ubuntu is not enough on its own, and the reason is the archive rather than the
distribution. `snapshot.ubuntu.com` begins in 2023, and Ubuntu never published
some versions at all: CVE-2021-41773 is Apache 2.4.49, and noble carries
2.4.57/2.4.58, jammy 2.4.52, focal 2.4.41, bionic 2.4.29 - the vulnerable build
existed for ten days and no Ubuntu release ever shipped it. Debian did, and
`snapshot.debian.org` keeps 407 archived apache2 versions including four 2.4.49
builds, so that CVE resolves on exactly the machinery already here.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass

LP = "https://api.launchpad.net/1.0"
SNAPSHOT = "https://snapshot.debian.org"
VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
# The words that make a bound EXCLUSIVE, in one place because upper_bound
# and segments() must agree about them: a list that drifts would have the
# two halves of the same question answered differently.
#
# The CNA records' own words. "3.15 to less than 6.8" is how CVE-2024-1086
# reads, and the flattened field it comes from is literally
# `versions[0].lessThan`, so both spellings count - without them the bound
# was INCLUSIVE and 6.8.9, which carries the fix, satisfied it.
STRICT_WORDS = (
    "prior to", "before", "earlier than", "fixed in",
    "less than", "lessthan", "lower than", "up to but",
)
# A branch per segment. The extractor's phrasing of affected_range is NOT
# stable - the same redis advisory came back ">= 2.6, < 6.2.16; >= 7.0.0, ..."
# on one check and ">= 2.6, < 6.2.16 and >= 7.0.0, ..." on the next - so every
# separator it uses has to count, or the segments silently collapse to none and
# the single-bound path answers instead. ";", " and ", and the comma that
# starts a fresh "from X through Y" clause, which is how tomcat's read.
# A comma that separates BRANCHES is followed by a version; a comma INSIDE one
# branch is followed by a comparison operator. Tomcat's advisory reads
#   "11.0.0-M1 through 11.0.2, 10.1.0-M1 through 10.1.34, 9.0.0.M1 through
#    9.0.98, 8.5.0 through 8.5.100"
# and without the last alternative that was ONE segment, so the single-bound
# path took the first and last tokens it found - a range from 11.0.0-M1 down to
# 8.5.100, which matches nothing. jammy ships tomcat9 9.0.58, squarely inside
# the third branch, and the check still refused it as "no built release
# publishes tomcat9".
#
# Redis and Grafana write the other shape - ">= 7.0.0, < 7.2.6; >= 6.2.0,
# < 6.2.14" - where the comma joins a floor to its ceiling and the SEMICOLON
# separates branches. Splitting on every comma would halve those into
# nonsense, which is why this looks for a version after the comma and not just
# a comma.
SEGMENT_SPLIT = re.compile(r";|\s+and\s+|,\s*(?=from\b)|,\s*(?=v?\d)", re.IGNORECASE)

# Debian's index answers for every port it ever built, and these cannot be
# installed on amd64: "sudo 1.8.2 to 1.8.31p2" resolved to 1.8.2-2+hurd.1,
# which would have failed at apt-get install with nothing saying why.
PORT_ONLY = re.compile(r"\+(?:hurd|kfreebsd|hppa|sparc|m68k)\b")
# A `~` tail sorts below the version it hangs off, but only some of those tails
# mean "not yet that version". `~bpo11+1` is a BACKPORT: same upstream code,
# rebuilt for an older suite - so 5.16.11-1~bpo11+1 IS the kernel that fixed
# Dirty Pipe, and treating every `~` as a pre-release let it through a strict
# bound of 5.16.11. Measured, after I had written exactly that bug.
PRE_RELEASE = re.compile(r"~(?:rc|alpha|beta|pre|dev|git|exp|snapshot)", re.IGNORECASE)
# Launchpad pages at 75 entries; a handful of pages is plenty to see whether a
# version line was ever published, and bounds a pathological package.
MAX_PAGES = 4


@dataclass(frozen=True)
class Release:
    version: str
    suite: str
    image_id: str
    artifact_id: str
    # Which archive's snapshots this release's serials index, and so which
    # upstream the broker's apt proxy points at for this job.
    archive: str
    # bionic's apt is 1.6 and does not read deb822 .sources files, so its
    # sources list has to be written in the one-line format.
    sources_format: str


# Newest first: when several releases carry a vulnerable version, the newest is
# the closest thing to a system someone might still be running.
# DEBIAN FIRST, which is an ordering by how well each archive can actually be
# dated rather than by how new the release is.
#
# Order matters because by_package() - the path an advisory takes when it names
# no version at all - returns the first release that carries the package, and
# because usable[0] is the fallback. Ubuntu was first, so every such advisory
# got an Ubuntu lab, and Ubuntu's archive has two gaps Debian's does not:
#
#   * snapshot.ubuntu.com only captured the -updates and -security pockets from
#     about 2023-06. Before that a job gets the release pocket alone, measured:
#     dists/jammy-updates/Release is 404 at 20220217 and 200 at 20230601.
#   * the base images are built from CURRENT cloud images, so their installed
#     packages are newer than an early serial can serve, and apt refuses to act
#     on a version no source carries - "Reinst Failed because of libatomic1",
#     then "Holding Back redis-server". Re-pinning to a release-day image is the
#     clean answer and focal's 2020 build does not boot under this builder: no
#     initrd on the kernel command line, so no virtio_blk, so no root disk.
#
# Debian has neither gap. snapshot.debian.org carries the full pocket history,
# and sid is always NEWER than the bullseye base, so apt only ever upgrades -
# it never needs a version the archive has stopped serving. That is why
# CVE-2021-41773 reproduced end to end on sid while every Ubuntu-path job died
# in provisioning.
#
# A version-matched advisory is unaffected: resolve() asks every built release's
# dated index and takes the one that actually carries the affected version, so
# this changes only which release answers FIRST, not which answers correctly.
RELEASES = (
    # Debian *unstable*, on a bullseye userland, and both halves of that are
    # measured rather than chosen.
    #
    # sid, because a stable suite backports a fix without changing the upstream
    # version, so a version match there means nothing. bullseye's apache2 went
    # 2.4.48-3.1 -> 2.4.48-3.1+deb11u1 -> 2.4.51-1~deb11u1: it never carried a
    # vulnerable 2.4.49 at all, and the 2.4.49-1~deb11u1 build that does exist
    # first appeared on 2021-10-08, three days after the advisory. sid at
    # 20211004 is 2.4.49-4, genuine unpatched upstream, and 2.4.50-1 two days
    # later.
    #
    # bullseye as the base, because the userland has to be of the serial's era.
    # A bookworm image is a 2023 userland, and resolving 2021 sid packages onto
    # it asks apt to reconcile a two-year gap in every shared library. sid in
    # October 2021 and bullseye (August 2021) are two months apart.
    Release("11", "sid", "debian-11-generic", "debian-11-generic-image", "debian", "deb822"),
    Release("24.04", "noble", "ubuntu-24.04-generic", "ubuntu-generic-image", "ubuntu", "deb822"),
    Release("22.04", "jammy", "ubuntu-22.04-generic", "ubuntu-jammy-generic-image", "ubuntu", "deb822"),
    Release("20.04", "focal", "ubuntu-20.04-generic", "ubuntu-focal-generic-image", "ubuntu", "deb822"),
    Release("18.04", "bionic", "ubuntu-18.04-generic", "ubuntu-bionic-generic-image", "ubuntu", "oneline"),
)
# 16.04 is not here: snapshot.ubuntu.com answers 404 for xenial's base suite at
# a 2024 serial, because the release has moved to old-releases. apt update would
# fail on the first index it asked for.


@dataclass(frozen=True)
class Resolution:
    release: Release
    package: str
    # The prefix the advisory named, which is what readiness asserts: apt
    # installs the newest build at the serial, and that is not necessarily the
    # exact publication found here.
    prefix: str
    # One version the archive is known to carry, for the plan to show.
    version: str
    # False when the match came from the fallback prefix rather than the
    # version the advisory actually names - "2.4" answering an advisory about
    # 2.4.49, which 2.4.58 satisfies with the fix already in it. The run is
    # still allowed, because an advisory naming a range genuinely has no exact
    # version to match, but it is not the same class of evidence and nothing
    # downstream can tell from the prefix alone: readiness is handed this
    # prefix and asserts exactly as much as it says.
    exact: bool = True


def existed(item: Release, serial: str) -> bool:
    """Whether this release was published by the time of this serial.

    An Ubuntu version IS its release date - 24.04 is April 2024 - so no table
    is needed. sid is rolling and has always existed.

    Without this the fallback was simply RELEASES[0], the newest build, and a
    CVE whose advisory names no version got noble at whatever serial its
    publication date gave. CVE-2022-0543's serial is 20220217 and noble did
    not exist for another two years, so the job provisioned, asked the proxy
    for dists/noble/Release, and died on a 404 that read like a broken mirror.
    """
    if item.archive != "ubuntu":
        return True
    year, month = item.version.split(".")[:2]
    return f"20{year}{month}01" <= serial[:8]


def fallback_for(usable: Sequence[Release], serial: str) -> Release | None:
    """The newest usable release that existed at this serial.

    RELEASES is newest-first, so the first match is the newest. None when the
    serial predates every build, which is a refusal rather than a release to
    guess at.
    """
    return next((item for item in usable if existed(item, serial)), None)


def dump(resolution: Resolution | None) -> str:
    """A Resolution as JSON, so a rebuild can replay the release that answered.

    The alternative is re-asking every built release's dated index, which is a
    network round trip each and can answer differently - or refuse - months
    after the run being reproduced.

    asdict nests the whole Release; restore looks that release up by its
    artifact_id rather than trusting the nested copy, so a stored release this
    build no longer carries yields None instead of a half-real target.
    """
    return json.dumps(asdict(resolution)) if resolution is not None else "{}"


def restore(payload: str) -> Resolution | None:
    """The Resolution that dump() wrote, or None.

    None for every unusable case - absent, malformed, or naming a release this
    build no longer has - because the caller's fallback is the same in all of
    them, and a rebuild that cannot replay the resolution should decline rather
    than quietly provision a different suite.
    """
    try:
        stored = json.loads(payload or "{}")
    except ValueError:
        return None
    if not isinstance(stored, dict):
        return None
    want = str((stored.get("release") or {}).get("artifact_id") or "")
    found = next((item for item in RELEASES if item.artifact_id == want), None)
    if found is None:
        return None
    return Resolution(
        release=found,
        package=str(stored.get("package") or ""),
        prefix=str(stored.get("prefix") or ""),
        version=str(stored.get("version") or ""),
        exact=bool(stored.get("exact", True)),
    )


def version_prefixes(affected_range: str) -> list[str]:
    """Version prefixes to accept, most specific first.

    The advisory gives prose ("8.4.0 ~ 8.4.26"), not a package version. The
    first version-shaped token in it is the one to match, and a shorter prefix
    is tried after it because the archive's version carries packaging suffixes
    the advisory never mentions.

    It stops at major.minor, and the pattern needs that much to match at all.
    A bare major would make 2.10.0 answer an advisory about 2.1.0 - a different
    series, installed and reproducing nothing - and an advisory that names only
    "version 7" has not said which build to install, so it resolves to nothing
    and the job is refused with that text quoted back.
    """
    found = VERSION_RE.findall(affected_range or "")
    if not found:
        return []
    # The LAST version named first, then the first. A two-ended range names its
    # floor first, and taking only that installed the oldest build in the
    # series: "sudo 1.8.2 to 1.8.31p2" resolved to 1.8.2 from 2011, and
    # "kernel 5.8 to 5.16.11" to 5.8.14, when the newest affected build is both
    # more like what someone runs and far more likely to still be in an
    # archive. The floor's prefixes stay as the fallback, because a range can
    # name a ceiling no archive carries while carrying the floor's series.
    prefixes: list[str] = []
    for token in (found[-1], found[0]):
        parts = token.split(".")
        for count in reversed(range(len(parts))):
            item = ".".join(parts[: count + 1])
            if item.count(".") >= 1 and item not in prefixes:
                prefixes.append(item)
    return prefixes


def upper_bound(
    affected_range: str, fixed_versions: list[str], prefix: str = ""
) -> tuple[str, bool] | None:
    """The newest version an install may be, and whether it is itself affected.

    Without this the fallback prefix installs the FIX. "< 1.2.23" gives
    prefixes ["1.2.23", "1.2"]; no archive carries 1.2.23 itself, so "1.2"
    matched and the newest 1.2.x won - Cacti 1.2.26, five releases past the
    fix. The job then provisions, reaches readiness (which only asserts what
    the prefix says) and the PoC fails against a patched package, which looks
    exactly like a PoC that does not work. The same happened for any exact
    version the archive never published.

    fixed_versions is the best evidence and the advisory states it; it had been
    extracted and used nowhere. Failing that the range's own words say which
    way the bound points: "< 1.2.23" excludes it, "3.2.1 and below" includes
    it, and a bare "2.4.49" includes it, which is what lets sid's 2.4.49-4
    still resolve.
    """
    if fixed_versions:
        # The fix for THIS series. An advisory usually fixes several branches
        # at once - Ghostcat names 9.0.31, 8.5.51 and 7.0.100 - and the
        # smallest of those is 7.0.100, which would bound a tomcat9 install
        # below every 9.x build in any archive and refuse a CVE that resolves
        # perfectly well. The prefix being tried says which series is wanted.
        # Series first, major second. Metabase's advisory fixes 0.46.6.1,
        # 0.45.4.1, 0.44.7.1 and 0.43.7.2 - all major 0 - so matching on the
        # major alone would bound a 0.46 install below 0.43.7.2 and refuse it.
        for depth in (2, 1):
            scope = ".".join(prefix.split(".")[:depth])
            same = [
                item
                for item in fixed_versions
                if item == scope or item.startswith(scope + ".")
            ]
            if same:
                return min(same, key=_version_key), False
        return min(fixed_versions, key=_version_key), False
    found = list(VERSION_RE.finditer(affected_range or ""))
    if not found:
        return None
    # The LAST version named, not the first. A two-ended range puts the ceiling
    # at the end - "2.0.0 - 2.1.3", "8.4.0 ~ 8.4.26" - and taking the first
    # bound a range at its own floor, which excluded every version in it.
    last = found[-1]
    start = found[-2].end() if len(found) > 1 else 0
    # Only the words between the previous version and this one, so a "before"
    # belonging to an earlier clause cannot make this bound strict.
    before = affected_range[start : last.start()].lower()
    # And what follows it: a pre-release marker says the bound is BELOW the
    # release it hangs off, so every build in that series is at or past the
    # fix. CVE-2022-0847's record says "Linux Kernel 5.17 rc6" with status
    # affected; VERSION_RE captures "5.17", the rc6 is dropped, and an
    # inclusive 5.17 then admitted 5.17.11 - nine point releases past the fix,
    # which went in at rc6. Measured, and it is how Dirty Pipe resolved to a
    # patched kernel.
    after = affected_range[last.end() : last.end() + 12].lower()
    marked = any(mark in after for mark in ("rc", "alpha", "beta", "-pre", " pre"))
    strict = (
        ("<" in before and "=" not in before)
        or any(word in before for word in STRICT_WORDS)
        or marked
    )
    # A `~` in the BOUND says the bound is itself a pre-release, which this
    # harness cannot order against another one: rc8 is past rc6 and both read
    # as "5.17". So the whole series is excluded, which is right here - every
    # 5.17 build, rc or release, carries the fix that went in at rc6 - and
    # conservative in the rare case where an earlier rc would have qualified.
    return (f"{last.group(0)}~rc" if marked else last.group(0)), not strict


def within(version: str, bound: str, affected: bool) -> bool:
    """Is ``version`` at or below ``bound``, comparing upstream parts only?

    Truncated to the bound's own depth because the archive's version carries
    packaging the advisory never mentions: 1.2.22+ds1-1 is upstream 1.2.22 and
    must pass an inclusive bound of 1.2.22, while its full key sorts above it.
    """
    want = [int(n) for n in re.findall(r"\d+", bound)]
    key = _version_key(version)
    got = key[1][: len(want)]
    # A pre-release of the bound sorts BELOW it, and the digits alone cannot
    # say so: 1.2.0~beta2 reads as [1, 2, 0], equal to a strict bound of 1.2.0,
    # and was excluded although it is exactly the kind of build that is still
    # affected. Debian ships these - cacti's archive carries 1.2.0~beta2+ds1-1.
    # A pre-release of the BOUND ITSELF, which needs the whole digit list and
    # not the truncated one: 5.17.1-1~exp1 is a pre-release of 5.17.1, which is
    # past a bound of 5.17, and comparing [5, 17] to [5, 17] called it below.
    if (
        key[1] == want
        and key[2] == 0
        and PRE_RELEASE.search(version)
        and "~" not in bound
    ):
        return True
    return got <= want if affected else got < want


def at_least(version: str, floor: str) -> bool:
    """Is ``version`` at or above ``floor``, comparing upstream parts only?

    The mirror of within(), truncating to the floor's own depth for the same
    reason. Needed only for multi-segment ranges, and there it is what stops
    the GAPS: redis 6.5 is above the first branch's 6.2.16 ceiling and below
    the second branch's 7.0.0 floor, so no branch covers it.
    """
    want = [int(number) for number in re.findall(r"\d+", floor)]
    return _version_key(version)[1][: len(want)] >= want


def segments(affected_range: str) -> tuple[tuple[str, str, bool], ...]:
    """(floor, ceiling, ceiling-itself-affected) for each branch named.

    A modern advisory states its range PER BRANCH. redis CVE-2024-31449 reads
    ">= 2.6, < 6.2.16; >= 7.0.0, < 7.2.6; >= 7.3.0, < 7.4.1", and upper_bound
    collapses that to ONE bound - so 7.0.15, which the second branch plainly
    covers, was compared against 6.2.16 and reported as not affected by this
    CVE. Four refusals in one sweep were that shape.

    Empty for a single-segment range, which keeps every existing caller on the
    upper_bound path: this answers only the question that path cannot.
    """
    found = []
    for part in SEGMENT_SPLIT.split(affected_range or ""):
        tokens = VERSION_RE.findall(part)
        if len(tokens) < 2:
            continue
        # Only the words BETWEEN the two versions, which is what upper_bound
        # looks at and for the same reason: ">= 7.0.0, < 7.2.6" read whole
        # contains an "=" from its own FLOOR, so the bound tested as inclusive
        # and 7.2.6 - the version that fixed that branch - counted as affected.
        lowered = part.lower()
        between = lowered.rsplit(tokens[-1].lower(), 1)[0]
        between = between.split(tokens[0].lower(), 1)[-1]
        strict = ("<" in between and "=" not in between) or any(
            word in between for word in STRICT_WORDS
        )
        found.append((tokens[0], tokens[-1], not strict))
    return tuple(found) if len(found) > 1 else ()


def published_versions(
    package: str, suite: str, fetch_fn: object, archive: str = "ubuntu"
) -> set[str]:
    """Every binary version of ``package`` the archive is known to carry.

    Both archives answer the same question and neither needs a model to do it,
    but they answer it differently. Launchpad is per release, so the reply is
    what *this suite* published. Debian's snapshot index is per package across
    the whole archive's history, so the reply is what Debian ever carried and
    the serial is what decides whether this job gets it - a version that
    existed in 2021 is not in a 2024 serial of sid, and readiness says so.
    """
    if archive == "debian":
        # .body, not .text: text is the reader's rendering and is not JSON.
        try:
            payload = json.loads(fetch_fn(f"{SNAPSHOT}/mr/binary/{package}/").body)  # type: ignore[operator]
        except Exception:  # noqa: BLE001 - an unavailable index is "unknown"
            return set()
        return {
            str(entry.get("binary_version") or "")
            for entry in payload.get("result") or []
            if entry.get("binary_version")
        }
    url = (
        f"{LP}/ubuntu/+archive/primary?ws.op=getPublishedBinaries"
        f"&binary_name={package}&exact_match=true"
        f"&distro_arch_series={LP}/ubuntu/{suite}/amd64"
    )
    versions: set[str] = set()
    for _page in range(MAX_PAGES):
        try:
            # .body, not .text: text is the reader's rendering and is not JSON.
            payload = json.loads(fetch_fn(url).body)  # type: ignore[operator]
        except Exception:  # noqa: BLE001 - an unavailable index is "unknown"
            return versions
        for entry in payload.get("entries") or []:
            version = str(entry.get("binary_package_version") or "")
            if version:
                versions.add(version)
        following = str(payload.get("next_collection_link") or "")
        if not following:
            break
        url = following
    return versions


def deb_url(package: str, affected_range: str, fetch_fn: object) -> str:
    """Debian's own URL for a .deb of the affected version, or "".

    The approval card exists because no BUILT release carries the version. The
    archive-wide snapshot index frequently still does, and offering that URL
    turns the card from "paste something" into "is this it?". Two requests:
    binfiles lists one {architecture, hash} per architecture, and /file/<hash>
    serves the file. Measured for apache2 2.4.49-4 amd64 at 268632 bytes,
    which is byte for byte the .deb blasty's PoC vendors.

    The address is a SHA-1 because that is how snapshot's store is keyed. It is
    an address and not the integrity story: what the job installs is pinned by
    the sha256 the approval computes over the bytes the host fetched.
    """
    prefixes = version_prefixes(affected_range)
    if not package or not prefixes:
        return ""
    versions = sorted(
        (
            item
            for item in published_versions(package, "sid", fetch_fn, "debian")
            if _matches(item, prefixes[0])
        ),
        key=_version_key,
    )
    if not versions:
        return ""
    try:
        binfiles = json.loads(
            fetch_fn(f"{SNAPSHOT}/mr/binary/{package}/{versions[-1]}/binfiles").body  # type: ignore[operator]
        )
        hashes = [
            entry["hash"]
            for entry in binfiles.get("result") or []
            if entry.get("architecture") in {"amd64", "all"} and entry.get("hash")
        ]
        if not hashes:
            return ""
        # NOT /file/<hash>. That URL carries no suffix, and both the approval
        # endpoint and the setup step read a file's install off its name - so
        # the form filled in a URL its own endpoint then refused. The archive
        # path carries the real name, which also makes the suggestion legible:
        # an operator can read `apache2_2.4.49-4_amd64.deb` and decide.
        info = json.loads(
            fetch_fn(f"{SNAPSHOT}/mr/file/{hashes[0]}/info").body  # type: ignore[operator]
        )
        at = (info.get("result") or [{}])[0]
        serial, path, name = at.get("first_seen"), at.get("path"), at.get("name")
        if not (serial and path and name):
            return ""
        return f"{SNAPSHOT}/archive/debian/{serial}{path}/{name}"
    except Exception:  # noqa: BLE001 - no suggestion is a fine answer
        return ""


def _version_key(version: str) -> tuple[int, list[int], int, str]:
    """Order archive versions by value rather than by spelling.

    `sorted()` on strings is what resolve used, and it is wrong in a way that
    reaches the plan: Debian's archive-wide index holds 407 apache2 versions,
    252 of them matching the loose prefix "2.4", and the lexically largest of
    those is `2.4.9-2` - from 2014 - while the newest is `2.4.71-1`. The job
    installed what the plan named, so the plan named the wrong build.

    Not a full dpkg comparison. Three things decide the answer here and they
    are the three implemented: a higher epoch always wins; a `~` marks a
    pre-release of the version before it and so sorts BELOW the plain one, as
    `2.4.49-1~deb11u1` is older than `2.4.49-1`; and everything else is its
    numeric components in order.
    """
    epoch, _, rest = version.partition(":")
    if not rest or not epoch.isdigit():
        epoch, rest = "0", version
    head, _, tail = rest.partition("~")
    return (int(epoch), [int(n) for n in re.findall(r"\d+", head)], 0 if tail else 1, version)


def _matches(version: str, prefix: str) -> bool:
    # Strip a Debian epoch ("1:7.2.10-1") before comparing: the advisory never
    # carries one.
    upstream = version.split(":", 1)[-1]
    if upstream == prefix or not upstream.startswith(prefix):
        return upstream == prefix
    # Any boundary that is not another digit. Requiring "." or "-" made every
    # upstream version with a letter after its numbers invisible: Debian sid
    # carries OpenSSH 1:9.7p1-2, the exact build CVE-2024-6387 affects, and
    # "9.7p1-2" starts with neither "9.7." nor "9.7-" - so the CVE was refused
    # as if no archive had it. OpenSSL's 1.1.1k and sudo's 1.9.5p2 are the
    # same shape. The digit test is what still keeps 2.1 from matching 2.10.
    return not upstream[len(prefix) : len(prefix) + 1].isdigit()


def unresolved(packages: list[str], affected_range: str) -> str:
    """Why nothing resolved, said in terms of the thing that is missing.

    "no built release publishes redis at 'n/a'" blames the archives for an
    advisory that named no version: CVE-2022-0543 is a Debian packaging flaw
    and its range came back as "n/a", so there was never a version to look
    for. The two cases are not the same gap and only one of them is about an
    archive.
    """
    if not version_prefixes(affected_range):
        return (
            f"the advisory names no version to match - affected_range is "
            f"{affected_range!r} - so no archive can be asked which build to "
            f"install for {' or '.join(packages)}. A version, or an approved "
            "download of the affected build, is what this needs"
        )
    return (
        f"no built release publishes {' or '.join(packages)} at "
        f"{affected_range!r} below the version that fixed it"
    )


def by_package(
    packages: list[str], releases: tuple[Release, ...], fetch_fn: object
) -> Resolution | None:
    """The newest release publishing the package at all, for an advisory that
    names no version.

    CVE-2021-4034's record says "all": pkexec carried the flaw from 2009 and
    only the per-distro fix bounds it, so there is no version to match. The
    build still comes out right without one, because the apt serial is already
    one day before publication - measured for that CVE, sid at 20220124 serves
    policykit-1 0.120-2 and Debian's fix, 0.120-3, was first seen 2022-01-25,
    the day of the advisory. What cannot be done is ASSERT a version, so the
    prefix and version are empty, readiness skips its check, and the target
    carries a caveat saying the build was chosen by date.
    """
    for item in releases:
        for package in packages:
            if published_versions(package, item.suite, fetch_fn, item.archive):
                return Resolution(
                    release=item, package=package, prefix="", version="", exact=False
                )
    return None


def verdict(resolution: Resolution | None, affected_range: str) -> str:
    """What the apt channel is reported to have decided.

    A loose match is said out loud: the plan used to read "apache2
    2.4.58-1ubuntu8.4" for an advisory about 2.4.49 and leave the reader to
    notice the version was not the one named. An empty prefix is the by_package
    case, where there was no version to match and the serial decided - and the
    inline version of this indexed version_prefixes()[0], which is empty
    exactly then.
    """
    if resolution is None:
        return "nothing to install"
    # Two different empty prefixes: by_package found no version to match at
    # all and names none, while the ceiling sweep found one and declines to
    # claim its series.
    if not resolution.prefix and not resolution.version:
        return (
            f"{resolution.package}, whatever version the serial one day before "
            "the advisory carries - the advisory names none to match"
        )
    if resolution.exact:
        return f"{resolution.package} {resolution.version}"
    named = version_prefixes(affected_range)
    if not resolution.prefix or resolution.prefix not in named:
        # The ceiling sweep: no prefix matched, so this is the newest build the
        # archive EVER carried below the bound - which for a stable series can
        # be years after the advisory and carry a backported fix.
        # CVE-2023-0386 picks 6.1.190 against a 2023 bound of 6.2. The build
        # that actually installs is the serial's, one day before publication;
        # this version only chose the release and the readiness prefix.
        return (
            f"{resolution.package} below {named[0] if named else 'the fix'}, "
            f"shown as {resolution.version} - the newest the archive ever "
            "carried under that bound. The serial one day before the advisory "
            "decides which build installs"
        )
    return (
        f"{resolution.package} {resolution.version} - matched on "
        f"{resolution.prefix}, not the {named[0]} "
        "the advisory names, so this may carry the fix"
    )


def available(releases: tuple[Release, ...], resolved_artifacts: set[str]) -> tuple[Release, ...]:
    return tuple(item for item in releases if item.artifact_id in resolved_artifacts)


def resolve(
    packages: list[str],
    affected_range: str,
    releases: tuple[Release, ...],
    fetch_fn: object,
    fixed_versions: list[str] | None = None,
) -> Resolution | None:
    """The newest available release publishing a version the advisory names.

    Prefixes outside releases, which is the whole point of the nesting.
    version_prefixes falls back from "2.4.49" to "2.4" so an advisory that
    names a range still matches a real build; nested the other way round that
    fallback was tried on the first release before the exact prefix was tried
    on any later one. CVE-2021-41773 names Apache 2.4.49, which only Debian
    sid ever carried unpatched, and it resolved to noble's 2.4.58 on "2.4" -
    the fix already in it - without querying Debian at all.

    Every lookup is made, none is remembered. A dict keyed on (suite, package)
    would save the repeat the fallback prefix causes - at most one extra round
    per release, since there are at most two prefixes - but it would also mean
    the archive's answer is reported once and reused, so a lookup that returns
    the wrong set, or stops returning anything, is invisible after its first
    call. The queries are the record of what was asked: keeping them one to
    one with the questions is worth more than the round trips.
    """
    prefixes = version_prefixes(affected_range)
    if not prefixes or not packages:
        return None
    for prefix in prefixes:
        ceiling = upper_bound(affected_range, fixed_versions or [], prefix)
        for release in releases:
            for package in packages:
                published = published_versions(
                    package, release.suite, fetch_fn, release.archive
                )
                hits = sorted(
                    (
                        item
                        for item in published
                        if _matches(item, prefix)
                        and (ceiling is None or within(item, *ceiling))
                        and not PORT_ONLY.search(item)
                    ),
                    key=_version_key,
                )
                if hits:
                    return Resolution(
                        release=release,
                        package=package,
                        prefix=prefix,
                        version=hits[-1],
                        exact=prefix == prefixes[0],
                    )
    # No build matched either endpoint's prefix, and for a wide range that is
    # the normal case rather than a dead end: "3.15 to less than 6.8" is every
    # kernel in between and neither endpoint is a build anyone shipped, while
    # "Linux Kernel 5.17 rc6" names only a series this harness excludes whole.
    # Below the ceiling is what the ceiling MEANS, so the newest build below it
    # is the answer. Only with a ceiling - without one nothing has been said
    # about which builds are affected.
    ceiling = upper_bound(affected_range, fixed_versions or [], prefixes[0])
    if ceiling is None:
        return None
    # And the range's FLOOR, when it names one. Without it this sweep found
    # Debian's grafana 2.6.0 for an advisory about Grafana 8.0.0 to 8.3.0 -
    # the package name collides and 2.6.0 is indeed "below the ceiling", so a
    # regression this very function introduced turned a correct refusal into a
    # job against unrelated software. A range with ONE version token has no
    # floor - "before 6.2", "Linux Kernel 5.17 rc6" mean everything under it -
    # so the floor applies only when two or more are named.
    tokens = VERSION_RE.findall(affected_range or "")
    floor = [int(part) for part in re.findall(r"\d+", tokens[0])] if len(tokens) > 1 else []
    # And the same major as the ceiling, which is what stops the other half of
    # the collision: Debian's `jenkins` is 1.565.3 from 2014 and CVE-2024-23897
    # is about 2.441, a single-token range with no floor to catch it, so
    # "below the ceiling" matched a decade-old different product under the same
    # name. This refuses a legitimate "before 2.0" against an archive carrying
    # 1.9, which is a false NEGATIVE the operator can answer by approving a
    # .deb - where the alternative is a job run against unrelated software and
    # reported as a reproduction.
    top = _version_key(ceiling[0])[1][:1]
    for item in releases:
        for package in packages:
            under = sorted(
                (
                    found
                    for found in published_versions(
                        package, item.suite, fetch_fn, item.archive
                    )
                    if within(found, *ceiling)
                    and not PORT_ONLY.search(found)
                    and _version_key(found)[1][: len(floor)] >= floor
                    and _version_key(found)[1][:1] == top
                ),
                key=_version_key,
            )
            if under:
                # An EMPTY prefix, deliberately. The newest build below the
                # ceiling can postdate the advisory by years - measured:
                # linux-image-amd64 6.1.190-1 was first seen 2026-10-17 for a
                # 2023 CVE, one of 493 candidates under that bound and 70 in
                # its own series - and dating them is one HTTP call each with
                # no ordering to bisect on, since 5.10.92-2 was published
                # AFTER 5.16.10-1. So this does not claim a series: readiness
                # skips its version check, the caveat says the build was
                # chosen by the serial, and the changelog check is what
                # catches a build that already carries the fix.
                return Resolution(
                    release=item,
                    package=package,
                    prefix="",
                    version=under[-1],
                    exact=False,
                )
    return None
