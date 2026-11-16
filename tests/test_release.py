"""Choosing a release, which the snapshot serial cannot do.

The serial moves along one release's timeline. Crossing releases is a separate
question - "did any release we can boot ever publish this version?" - and it is
answered by the archive's own publication record rather than by a model, so a
wrong answer costs a query instead of a 2.5 GB image build.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from xentry import release
from xentry.fetch import json_to_text


@dataclass
class FakeFetched:
    """Shaped like the real Fetched, which is the point.

    It used to carry only `text`, so nothing noticed when `text` became a
    rendering for a reader rather than the bytes: the resolver's json.loads
    started failing, its except swallowed that, and every lookup quietly
    returned no versions at all. The fake now renders the same way the real
    fetch does, so a caller that parses `text` fails here first.
    """

    payload: str

    @property
    def body(self) -> bytes:
        return self.payload.encode()

    @property
    def text(self) -> str:
        return json_to_text(self.payload)


class FakeArchive:
    """Both archives' version indexes, as one lookup table.

    They answer the same question through different URLs: Launchpad per suite,
    Debian's snapshot index per package across the whole archive. A fake that
    only understood Launchpad recorded no Debian query at all, which made it
    look as though the Debian release was never consulted.
    """

    def __init__(self, published: dict[tuple[str, str], list[str]]) -> None:
        self.published = published
        self.queries: list[tuple[str, str]] = []

    def __call__(self, url: str) -> FakeFetched:
        if "snapshot.debian.org" in url:
            name = url.rstrip("/").rsplit("/", 1)[1]
            self.queries.append((name, "sid"))
            versions = self.published.get((name, "sid"), [])
            return FakeFetched(
                json.dumps(
                    {"result": [{"binary_version": v} for v in versions]}
                )
            )
        name = url.split("binary_name=", 1)[1].split("&", 1)[0]
        suite = url.rsplit("/ubuntu/", 1)[1].split("/", 1)[0]
        self.queries.append((name, suite))
        versions = self.published.get((name, suite), [])
        return FakeFetched(
            json.dumps(
                {
                    "total_size": len(versions),
                    "entries": [{"binary_package_version": v} for v in versions],
                }
            )
        )


ALL = release.RELEASES


# ------------------------------------------------------------- the prefixes ---


@pytest.mark.parametrize(
    ("affected", "expected"),
    [
        # The CEILING's prefixes first, then the floor's. A range names its
        # floor first, and taking only that installed the oldest build in the
        # series - sudo 1.8.2 from 2011 for a range ending at 1.8.31p2.
        ("8.4.0 ~ 8.4.26", ["8.4.26", "8.4", "8.4.0"]),
        ("before 7.2.11", ["7.2.11", "7.2"]),
        ("2.0.0 - 2.1.3", ["2.1.3", "2.1", "2.0.0", "2.0"]),
        ("1.8.2 to 1.8.31p2", ["1.8.31", "1.8", "1.8.2"]),
        # A bare major is never a prefix: 2.10 is not 2.1. An advisory that
        # names only a major has not said which build to install, so it
        # resolves to nothing and the job is refused.
        ("version 7 is affected", []),
        ("all versions", []),
        ("", []),
    ],
)
def test_version_prefixes_come_from_the_advisory_text(affected: str, expected: list[str]) -> None:
    assert release.version_prefixes(affected) == expected


# -------------------------------------------------------------- the lookup ---


def test_an_old_version_resolves_to_the_old_release() -> None:
    """The case the serial cannot reach: noble never shipped PHP 7.2."""
    archive = FakeArchive(
        {
            ("php7.2-cli", "bionic"): ["7.2.1-1", "7.2.7-0ubuntu0.18.04.2"],
            ("php7.2-cli", "jammy"): [],
            ("php7.2-cli", "noble"): [],
        }
    )
    found = release.resolve(["php7.2-cli"], "before 7.2.11", ALL, archive)
    assert found is not None
    assert found.release.version == "18.04"
    assert found.release.suite == "bionic"
    assert found.release.sources_format == "oneline"
    assert found.package == "php7.2-cli"
    assert found.prefix == "7.2"



def _asked_upto(package: str, suite: str) -> list[tuple[str, str]]:
    """Every release queried up to and including `suite`, in RELEASES order.

    The sweep asks each built release in turn and stops at the first that
    matches, so the trace depends on the ORDER, not just the winner. Computed
    here because that order is a policy that changes: Debian moved to the front
    once it was clear its archive is the only one with a complete pocket
    history, and three tests that hardcoded "noble is asked first" broke.
    """
    asked = []
    for item in ALL:
        asked.append((package, item.suite))
        if item.suite == suite:
            break
    return asked


def test_the_newest_release_carrying_it_wins() -> None:
    """When several carry the version, the newest is the closest thing to a
    system someone might still be running."""
    archive = FakeArchive(
        {
            ("widget", "noble"): ["2.0.9-1"],
            ("widget", "jammy"): ["2.0.4-1"],
            ("widget", "bionic"): ["2.0.1-1"],
        }
    )
    found = release.resolve(["widget"], "2.0.0 - 2.1.3", ALL, archive)
    assert found is not None
    assert found.release.version == "24.04"
    # Four prefixes now, in order: 2.1.3 and 2.1 from the ceiling, then 2.0.0
    # and 2.0 from the floor. Every release is asked on each in turn, and none
    # of that can be known without asking - stopping at the first release that
    # matched a LOOSE prefix is what made an advisory about Apache 2.4.49
    # resolve to noble's 2.4.58. Nothing is cached, so the sweep is visible.
    sweep = [("widget", item.suite) for item in ALL]
    assert archive.queries == sweep * 3 + _asked_upto("widget", "noble")


def test_an_exact_match_on_the_newest_release_still_costs_one_query() -> None:
    """The common case must not pay for the fix: when the advisory names the
    version noble actually publishes, the first prefix hits the first release
    and nothing else is asked."""
    archive = FakeArchive({("widget", "noble"): ["2.0.9-1"]})
    found = release.resolve(["widget"], "widget 2.0.9", ALL, archive)
    assert found is not None
    assert found.release.suite == "noble"
    assert found.prefix == "2.0.9"
    assert archive.queries == _asked_upto("widget", "noble")


def test_nothing_resolves_when_no_release_published_it() -> None:
    archive = FakeArchive({})
    assert release.resolve(["ghost"], "1.2.3", ALL, archive) is None
    # Every release was asked before giving up, in matrix order: once per
    # prefix - "1.2.3" then "1.2" - and once more for the ceiling sweep, which
    # is what answers a range whose endpoints nobody shipped. That includes the
    # Debian release through its own index.
    assert [suite for _name, suite in archive.queries] == [
        item.suite for item in ALL
    ] * 3
    assert "sid" in {suite for _name, suite in archive.queries}


def test_a_version_the_advisory_never_names_resolves_to_nothing() -> None:
    archive = FakeArchive({("widget", "noble"): ["2.0.9-1"]})
    assert release.resolve(["widget"], "all versions", ALL, archive) is None
    assert archive.queries == []


def test_an_epoch_does_not_hide_a_match() -> None:
    archive = FakeArchive({("widget", "noble"): ["1:2.0.9-1ubuntu1"]})
    found = release.resolve(["widget"], "2.0.0 - 2.1.3", ALL, archive)
    assert found is not None
    assert found.prefix == "2.0"


def test_a_near_miss_is_not_a_match() -> None:
    """2.10 is not 2.1, and installing it would reproduce nothing."""
    archive = FakeArchive(
        {
            ("widget", "noble"): ["2.10.0-1"],
            ("widget", "jammy"): [],
            ("widget", "bionic"): [],
        }
    )
    found = release.resolve(["widget"], "2.1.0 only", ALL, archive)
    assert found is None


def test_an_unreachable_archive_is_unknown_not_a_match() -> None:
    def broken(_url: str) -> Any:
        raise OSError("launchpad is down")

    assert release.resolve(["widget"], "2.0.0", ALL, broken) is None


def test_pagination_is_followed_but_bounded() -> None:
    pages: list[str] = []

    def paged(url: str) -> FakeFetched:
        pages.append(url)
        return FakeFetched(
            json.dumps(
                {
                    "entries": [{"binary_package_version": "9.9.9-1"}],
                    "next_collection_link": f"{release.LP}/next?page={len(pages)}",
                }
            )
        )

    assert release.published_versions("widget", "noble", paged) == {"9.9.9-1"}
    assert len(pages) == release.MAX_PAGES


# ------------------------------------------------------- what is available ---


def test_only_a_built_release_is_offered() -> None:
    """Resolving to an unbuilt image would turn a clean refusal into a late
    boot failure."""
    bionic = next(item for item in ALL if item.version == "18.04")
    assert release.available(ALL, set()) == ()
    assert release.available(ALL, {bionic.artifact_id}) == (bionic,)
    assert len(release.available(ALL, {item.artifact_id for item in ALL})) == len(ALL)


def test_the_matrix_spans_both_archives() -> None:
    """Ubuntu alone cannot reach a version it never published.

    CVE-2021-41773 is Apache 2.4.49: noble has 2.4.57/2.4.58, jammy 2.4.52,
    bionic 2.4.29, and snapshot.ubuntu.com begins in 2023 regardless. Debian
    carried 2.4.49 for ten days and its snapshot archive still has it.
    """
    archives = {item.archive for item in ALL}
    assert archives == {"ubuntu", "debian"}
    for item in ALL:
        assert item.archive in {"ubuntu", "debian"}, item
        assert item.artifact_id.startswith(item.archive), item


def test_an_exact_version_beats_a_loose_prefix_on_an_earlier_release() -> None:
    """The prefix loop used to sit INSIDE the release loop.

    version_prefixes falls back from "2.4.49" to "2.4" so that an advisory
    naming a range ("8.4.0 ~ 8.4.26") still matches the build the archive
    actually has. Nested the other way round, that fallback was tried on the
    first release before the exact prefix was tried on any later one - so
    CVE-2021-41773, which names Apache 2.4.49, resolved to noble's
    2.4.58-1ubuntu8.4 on the "2.4" prefix and never queried Debian at all.
    The job would have provisioned a build with the fix in it, run the PoC
    against it, and failed to reproduce for a reason nothing reported.

    Only Debian sid ever carried an unpatched 2.4.49; the versions below are
    what each suite really publishes.
    """
    published = {
        ("apache2", "noble"): ["2.4.58-1ubuntu8.4"],
        ("apache2", "jammy"): ["2.4.52-1ubuntu4.9"],
        ("apache2", "focal"): ["2.4.41-4ubuntu3.17"],
        ("apache2", "sid"): ["2.4.48-3.1", "2.4.49-4", "2.4.51-1"],
        ("apache2", "bionic"): ["2.4.29-1ubuntu4.27"],
    }
    fake = FakeArchive(published)
    got = release.resolve(["apache2"], "Apache HTTP Server 2.4.49", ALL, fake)
    assert got is not None
    assert got.release.archive == "debian", got
    assert got.version == "2.4.49-4", got
    assert got.prefix == "2.4.49", got
    # sid is asked FIRST now and matches the exact prefix, so the sweep stops
    # there and the releases behind it are never queried. The outcome is the
    # same one the old order reached after asking all five - 2.4.49-4 on sid -
    # for two fewer round trips.
    #
    # "every built release answers" is an invariant of REFUSING, not of
    # resolving: nothing is refused here, so there is nothing to justify. That
    # guarantee is asserted where it belongs, against the app's sweep, in
    # tests/test_generic_target.py.
    assert ("apache2", "sid") in fake.queries
    assert fake.queries == _asked_upto("apache2", "sid")


def test_the_loose_prefix_still_rescues_a_range_no_release_names_exactly() -> None:
    """The fallback is why the nesting was that way round; it has to survive.

    An advisory writing "8.4.0 ~ 8.4.26" yields the prefixes 8.4.0 then 8.4,
    and no archive publishes 8.4.0 - so the loose prefix is the only thing that
    resolves it, and it must still pick the newest release that has one.
    """
    published = {
        # Neither end of the range exactly: 8.4.0 and 8.4.26 are both absent,
        # so only the loose prefix can rescue this one.
        ("php8.4", "noble"): ["8.4.11-1ubuntu1"],
        ("php8.4", "jammy"): [],
        ("php8.4", "focal"): [],
        ("php8.4", "sid"): [],
        ("php8.4", "bionic"): [],
    }
    fake = FakeArchive(published)
    got = release.resolve(["php8.4"], "8.4.0 ~ 8.4.26", ALL, fake)
    assert got is not None
    assert got.release.suite == "noble", got
    assert got.prefix == "8.4", got
    assert got.version == "8.4.11-1ubuntu1", got

    # And when the ceiling IS published, that exact version wins instead of
    # the loose prefix - it is a version the advisory names as affected.
    named = FakeArchive({("php8.4", "noble"): ["8.4.26-1ubuntu1"]})
    exact = release.resolve(["php8.4"], "8.4.0 ~ 8.4.26", ALL, named)
    assert exact is not None and exact.prefix == "8.4.26" and exact.exact


def test_every_lookup_is_made_and_none_is_remembered() -> None:
    """Deliberately not memoised, and this is what says so.

    A dict keyed on (suite, package) would save the repeat the fallback prefix
    causes, but it would also report the archive's answer once and reuse it -
    so a lookup returning the wrong set, or returning nothing, would be
    invisible after its first call. The queries are the record of what was
    asked, and they stay one to one with the questions: two prefixes over five
    releases is ten lookups, then five more for the ceiling sweep that answers
    a range whose endpoints nobody shipped - fifteen, in that order.
    """
    published = {("apache2", suite): [] for suite in
                 ("noble", "jammy", "focal", "sid", "bionic")}
    fake = FakeArchive(published)
    assert release.version_prefixes("2.4.49") == ["2.4.49", "2.4"]
    assert release.resolve(["apache2"], "2.4.49", ALL, fake) is None
    expected = [("apache2", item.suite) for item in ALL] * 3
    assert fake.queries == expected, fake.queries


def test_a_loose_match_is_marked_as_one() -> None:
    """readiness is handed resolution.prefix and asserts exactly that much.

    An advisory naming a range has no exact version to match, so the fallback
    prefix is allowed - but "2.4" is satisfied by 2.4.58 with the fix in it,
    and nothing downstream can tell the difference from the prefix alone. The
    flag is what lets the plan say so.
    """
    exact = FakeArchive({("widget", "noble"): ["2.0.9-1"]})
    found = release.resolve(["widget"], "widget 2.0.9", ALL, exact)
    assert found is not None and found.exact and found.prefix == "2.0.9"

    loose = FakeArchive({("widget", "noble"): ["2.0.9-1"]})
    fallback = release.resolve(["widget"], "2.0.0 - 2.1.3", ALL, loose)
    assert fallback is not None
    assert fallback.prefix == "2.0"
    assert not fallback.exact, fallback
    # And the version it picked is not the one the advisory led with.
    assert fallback.version == "2.0.9-1"
    # The first prefix tried is the range's CEILING, which is the newest
    # version the advisory calls affected.
    assert release.version_prefixes("2.0.0 - 2.1.3")[0] == "2.1.3"


def test_an_official_deb_is_suggested_for_the_affected_version() -> None:
    """The approval card exists because no BUILT release carries the version.
    The archive-wide snapshot index frequently still does, and offering that
    URL turns "paste something" into "is this it?".
    """
    import json

    asked: list[str] = []

    def archive(url: str) -> Any:
        asked.append(url)
        if "/binfiles" in url:
            body: Any = {
                "result": [
                    {"architecture": "mips64el", "hash": "a" * 40},
                    {"architecture": "amd64", "hash": "d2e9d4de"},
                ]
            }
        elif "/mr/file/" in url:
            body = {
                "result": [
                    {
                        "archive_name": "debian",
                        "first_seen": "20211001T144836Z",
                        "name": "apache2_2.4.49-4_amd64.deb",
                        "path": "/pool/main/a/apache2",
                    }
                ]
            }
        else:
            body = {"result": [{"binary_version": v} for v in ("2.4.48-3.1", "2.4.49-4")]}
        return type("F", (), {"body": json.dumps(body).encode()})()

    url = release.deb_url("apache2", "Apache HTTP Server 2.4.49", archive)
    # An archive path, not /file/<sha1>: that has no suffix, and both the
    # approval endpoint and the setup step read a file's install off its name,
    # so the form filled in a URL its own endpoint then refused.
    assert url == (
        "https://snapshot.debian.org/archive/debian/20211001T144836Z"
        "/pool/main/a/apache2/apache2_2.4.49-4_amd64.deb"
    ), url
    assert url.endswith(".deb")
    # The newest build of the affected version, and amd64 rather than whichever
    # architecture the index happened to list first.
    assert "/mr/file/d2e9d4de/info" in asked[-1], asked
    assert any("/apache2/2.4.49-4/binfiles" in item for item in asked), asked


def test_no_suggestion_rather_than_a_wrong_one() -> None:
    import json

    def empty(_url: str) -> Any:
        return type("F", (), {"body": json.dumps({"result": []}).encode()})()

    assert release.deb_url("apache2", "2.4.49", empty) == ""
    assert release.deb_url("", "2.4.49", empty) == ""
    assert release.deb_url("apache2", "no version here", empty) == ""

    def broken(_url: str) -> Any:
        raise RuntimeError("snapshot is down")

    assert release.deb_url("apache2", "2.4.49", broken) == ""


def test_versions_are_ordered_by_value_not_by_spelling() -> None:
    """resolve sorted strings, and the plan named what it picked.

    Debian's archive-wide index holds 407 apache2 versions, 252 matching the
    loose prefix "2.4". The lexically largest of those is 2.4.9-2, from 2014;
    the newest is 2.4.71-1. So a loose match installed a decade-old build and
    reported it as the affected one. Three things decide the answer and all
    three are asserted here.
    """
    order = sorted(
        ["2.4.9-2", "2.4.58-1", "2.4.71-1", "2.4.49-1", "2.4.49-1~deb11u1",
         "2.4.49-4", "2.4.49-10", "1:7.0+32", "19"],
        key=release._version_key,
    )
    # Numeric components, so 2.4.9 is below 2.4.49 is below 2.4.71.
    assert order.index("2.4.9-2") < order.index("2.4.49-1")
    assert order.index("2.4.49-10") < order.index("2.4.58-1") < order.index("2.4.71-1")
    # A ~ is a PRE-release of what precedes it.
    assert order.index("2.4.49-1~deb11u1") < order.index("2.4.49-1")
    # A numeric revision, not a string one: -10 is newer than -4.
    assert order.index("2.4.49-4") < order.index("2.4.49-10")
    # A higher epoch always wins.
    assert order.index("19") < order.index("1:7.0+32")


def test_resolve_picks_the_newest_matching_build() -> None:
    published = {("apache2", "sid"): ["2.4.49-1", "2.4.49-10", "2.4.49-4",
                                      "2.4.49-1~deb11u1"]}
    archive = FakeArchive(published)
    found = release.resolve(["apache2"], "Apache 2.4.49", ALL, archive)
    assert found is not None
    # Lexically "2.4.49-4" wins; by value "-10" does.
    assert found.version == "2.4.49-10", found


def test_a_fallback_prefix_cannot_install_the_fix() -> None:
    """The bug this bound exists for.

    "< 1.2.23" gives prefixes ["1.2.23", "1.2"]. No archive published 1.2.23
    itself, so "1.2" matched and the NEWEST 1.2.x won - Cacti 1.2.26, three
    releases past the fix. The job provisioned, passed readiness (which only
    asserts what the loose prefix says) and the PoC failed against a patched
    package, which is indistinguishable from a PoC that does not work.
    """
    archive = FakeArchive(
        {
            ("cacti", "noble"): ["1.2.25+ds1-2", "1.2.26+ds1-1"],
            ("cacti", "jammy"): ["1.2.16+ds1-2ubuntu1", "1.2.19+ds1-2ubuntu1.1"],
        }
    )
    found = release.resolve(["cacti"], "< 1.2.23", ALL, archive)
    assert found is not None
    # Not noble, whose only 1.2.x builds are both the fix or later.
    assert found.version == "1.2.19+ds1-2ubuntu1.1"
    assert found.exact is False


def test_packaging_suffixes_do_not_push_a_version_over_its_own_bound() -> None:
    """1.2.22+ds1-1 is upstream 1.2.22 and satisfies an inclusive 1.2.22.

    Comparing full version keys put it above the bound, because the archive
    carries packaging the advisory never mentions.
    """
    archive = FakeArchive({("widget", "noble"): ["1.2.22+ds1-1", "1.2.26-1"]})
    found = release.resolve(["widget"], "1.2.22", ALL, archive)
    assert found is not None
    assert found.version == "1.2.22+ds1-1"


def test_the_ceiling_is_the_end_of_a_range_not_its_floor() -> None:
    """A two-ended range names its ceiling last."""
    assert release.upper_bound("2.0.0 - 2.1.3", []) == ("2.1.3", True)
    assert release.upper_bound("8.4.0 ~ 8.4.26", []) == ("8.4.26", True)
    # "<" excludes, "and below" includes, and a bare version includes itself -
    # which is what lets sid's 2.4.49-4 still answer CVE-2021-41773.
    assert release.upper_bound("< 1.2.23", []) == ("1.2.23", False)
    assert release.upper_bound("3.2.1 and below", []) == ("3.2.1", True)
    assert release.upper_bound("2.4.49", []) == ("2.4.49", True)
    # An advisory's own fixed version beats any reading of its prose.
    assert release.upper_bound("all 1.x", ["1.4.2", "1.9.0"]) == ("1.4.2", False)
    # A "before" in an earlier clause does not make this bound strict.
    assert release.upper_bound("before 2.3, now 1.0 - 2.9", []) == ("2.9", True)
    assert release.upper_bound("version 7", []) is None


def test_a_multi_branch_fix_bounds_the_branch_being_installed() -> None:
    """Ghostcat fixes 9.0.31, 8.5.51 and 7.0.100 in one advisory.

    The smallest of those is 7.0.100. Bounding a tomcat9 install below it
    excludes every 9.x build in every archive and refuses a CVE that resolves
    perfectly well - so the ceiling is the fix for the series being tried.
    """
    fixed = ["9.0.31", "8.5.51", "7.0.100"]
    assert release.upper_bound("9.0.0.M1 to 9.0.0.30", fixed, "9.0") == ("9.0.31", False)
    assert release.upper_bound("8.5.0 to 8.5.50", fixed, "8.5") == ("8.5.51", False)
    # No series in common: the smallest is the only safe reading.
    assert release.upper_bound("", fixed, "6.1") == ("7.0.100", False)
    # Metabase fixes eight versions across four series under two majors, so
    # the major alone is not the series: 0.46 must not be bounded by 0.43.7.2.
    metabase = ["0.46.6.1", "1.46.6.1", "0.45.4.1", "1.45.4.1", "0.44.7.1", "0.43.7.2"]
    assert release.upper_bound("", metabase, "0.46.6.1") == ("0.46.6.1", False)
    assert release.upper_bound("", metabase, "0.44") == ("0.44.7.1", False)
    # A fix in a later series than the prefix still bounds it, through the
    # major: exim's 4.87 is bounded by the 4.92 that fixed it.
    assert release.upper_bound("4.87 to 4.91", ["4.92"], "4.87") == ("4.92", False)
    archive = FakeArchive(
        {
            ("tomcat9", "noble"): ["9.0.70-1ubuntu1"],
            ("tomcat9", "focal"): ["9.0.27-1", "9.0.31-1"],
        }
    )
    found = release.resolve(
        ["tomcat9"], "Apache Tomcat 9.0.0.M1 to 9.0.0.30", ALL, archive, fixed
    )
    assert found is not None
    # Not 9.0.70, and not 9.0.31 either - that one IS the fix.
    assert found.version == "9.0.27-1"


def test_a_pre_release_of_the_bound_is_still_affected() -> None:
    """1.2.0~beta2 reads as [1, 2, 0] and a strict bound of 1.2.0 excluded it.

    The digits alone cannot say that a `~` build sorts below the version it is
    a pre-release of, and Debian ships these - cacti's archive carries
    1.2.0~beta2+ds1-1.
    """
    archive = FakeArchive({("widget", "noble"): ["1.2.0~beta2+ds1-1", "1.2.0-1"]})
    found = release.resolve(["widget"], "before 1.2.0", ALL, archive, ["1.2.0"])
    assert found is not None
    assert found.version == "1.2.0~beta2+ds1-1"


def test_the_newest_affected_build_is_preferred_over_the_oldest() -> None:
    """"sudo 1.8.2 to 1.8.31p2" resolved to 1.8.2-2+hurd.1, from 2011.

    Two faults in one answer: the floor of the range was tried first, so the
    oldest build in the series won, and Debian's index answers for every port
    it ever built, so the winner was a HURD binary amd64 cannot install - it
    would have failed at apt-get install with nothing saying why.
    """
    archive = FakeArchive(
        {
            ("sudo", "sid"): [
                "1.8.2-2+hurd.1",
                "1.8.31-1",
                "1.9.5-1",
                "1.9.5p2-1",
                "1.9.13-1",
            ]
        }
    )
    found = release.resolve(
        ["sudo"], "1.8.2 to 1.8.31p2 and 1.9.0 to 1.9.5p1", ALL, archive, ["1.9.5p2"]
    )
    assert found is not None
    # 1.9.5-1 is 1.9.5 without p2 - the newest build the advisory still names.
    assert found.version == "1.9.5-1"


def test_a_backport_of_the_fix_is_not_a_pre_release_of_it() -> None:
    """A bug I wrote and then measured.

    `~` sorts below the version it hangs off, so treating every `~` build as
    "not yet that version" let 5.16.11-1~bpo11+1 through a strict bound of
    5.16.11 - and that build IS the kernel that fixed Dirty Pipe, rebuilt for
    an older suite. Only rc/alpha/beta/pre/dev/git/exp tails mean pre-release.
    """
    assert release.within("1.2.0~beta2+ds1-1", "1.2.0", False) is True
    assert release.within("5.16.11-1~bpo11+1", "5.16.11", False) is False
    archive = FakeArchive(
        {("linux-image-amd64", "sid"): ["5.16.10-1", "5.16.11-1~bpo11+1", "5.16.11-1"]}
    )
    found = release.resolve(
        ["linux-image-amd64"], "5.8 to 5.16.11", ALL, archive, ["5.16.11", "5.15.25"]
    )
    assert found is not None
    assert found.version == "5.16.10-1"


def test_a_missing_version_is_not_an_empty_archive() -> None:
    """"no built release publishes redis at 'n/a'" blamed the archives.

    CVE-2022-0543 is a Debian packaging flaw whose range came back as "n/a",
    so there was never a version to look for - a different gap from an archive
    that genuinely does not carry the affected build, and only one of them is
    about an archive.
    """
    missing = release.unresolved(["redis"], "n/a")
    assert "names no version to match" in missing
    assert "approved download" in missing
    carried = release.unresolved(["couchdb"], "3.2.1 and below")
    assert "no built release publishes couchdb" in carried
    assert "below the version that fixed it" in carried


def test_a_letter_after_the_numbers_does_not_hide_a_version() -> None:
    """CVE-2024-6387 was refused as if no archive had it.

    Debian sid carries OpenSSH 1:9.7p1-2, the exact build regreSSHion
    affects, and `_matches` required the character after the prefix to be "."
    or "-" - so "9.7p1-2" matched neither "9.7." nor "9.7-". OpenSSL's 1.1.1k
    and sudo's 1.9.5p2 are the same shape. Any non-digit boundary counts now,
    and the digit test is what still keeps 2.1 from matching 2.10.
    """
    assert release._matches("1:9.7p1-2", "9.7") is True
    assert release._matches("8.5p1-1", "8.5") is True
    assert release._matches("1.9.5p2-1", "1.9.5") is True
    assert release._matches("1.1.1k-1", "1.1.1") is True
    assert release._matches("2.4.58-1", "2.4") is True
    # The series guard the old form existed for.
    assert release._matches("2.10.0-1", "2.1") is False
    assert release._matches("2.45.1-1", "2.4") is False
    archive = FakeArchive(
        {("openssh-server", "sid"): ["1:9.7p1-2", "1:9.8p1-1", "1:8.4p1-5"]}
    )
    found = release.resolve(
        ["openssh-server"], "8.5p1 through 9.7p1", ALL, archive, ["9.8p1"]
    )
    assert found is not None
    assert found.version == "1:9.7p1-2"


def test_an_advisory_with_no_version_still_picks_a_release() -> None:
    """CVE-2021-4034's record says "all", and that used to stop the job.

    There is nothing to match, but the build still comes out right: the apt
    serial is one day before publication, so whatever it carries predates the
    fix. Measured for that CVE - sid at 20220124 serves policykit-1 0.120-2,
    and Debian's fix, 0.120-3, was first seen on 2022-01-25. What cannot be
    done is assert a version, so the prefix and version come back empty and
    readiness skips its check.
    """
    archive = FakeArchive(
        {("policykit-1", "noble"): [], ("policykit-1", "sid"): ["0.120-2", "0.105-31"]}
    )
    assert release.resolve(["policykit-1"], "all", ALL, archive) is None
    found = release.by_package(["policykit-1"], ALL, archive)
    assert found is not None
    assert found.release.suite == "sid"
    assert found.prefix == "" and found.version == ""
    assert found.exact is False
    # And the verdict says which it is, rather than printing a blank version.
    said = release.verdict(found, "all")
    assert "whatever version the serial" in said
    assert "names none to match" in said


def test_the_verdict_does_not_index_an_empty_prefix_list() -> None:
    """The inline version of this read version_prefixes(range)[0] on the
    not-exact branch, which is empty exactly when by_package was used."""
    archive = FakeArchive({("widget", "noble"): ["2.0.9-1"]})
    dated = release.by_package(["widget"], ALL, archive)
    assert dated is not None
    release.verdict(dated, "all")  # no IndexError
    loose = release.resolve(["widget"], "2.0.0 - 2.1.3", ALL, archive)
    assert loose is not None
    assert "may carry the fix" in release.verdict(loose, "2.0.0 - 2.1.3")
    exact = release.resolve(["widget"], "widget 2.0.9", ALL, archive)
    assert exact is not None
    assert release.verdict(exact, "widget 2.0.9") == "widget 2.0.9-1"
    assert release.verdict(None, "anything") == "nothing to install"


def test_a_range_whose_endpoints_nobody_shipped_still_resolves() -> None:
    """Two measured CVEs, same gap.

    CVE-2024-1086's record reads "3.15 to less than 6.8" and CVE-2022-0847's
    reads "Linux Kernel 5.17 rc6": in the first neither endpoint is a build
    anyone shipped, and in the second the only series named is one this
    harness excludes whole, because rc8 is past rc6 and both read as "5.17".
    Below the ceiling is what the ceiling means, so the newest build below it
    is the answer - and before this, both were refused as if no archive
    carried a vulnerable kernel.
    """
    archive = FakeArchive(
        {
            ("linux-image-amd64", "sid"): [
                "6.7.12-1",
                "6.8.9-1",
                "5.16.18-1",
                "5.17~rc8-1~exp1",
                "3.16.59-1",
            ]
        }
    )
    wide = release.resolve(
        ["linux-image-amd64"], "3.15 to less than 6.8", ALL, archive, ["6.8"]
    )
    assert wide is not None
    assert wide.version == "6.7.12-1"
    # No prefix: the newest build below a bound can postdate the advisory, so
    # this does not claim a series for readiness to assert.
    assert wide.prefix == "" and wide.exact is False

    rc = release.resolve(["linux-image-amd64"], "Linux Kernel 5.17 rc6", ALL, archive)
    assert rc is not None
    # Not 5.17~rc8, which is past rc6 and carries the fix that went in there.
    assert rc.version == "5.16.18-1"


def test_a_pre_release_bound_excludes_its_whole_series() -> None:
    """rc8 is past rc6 and this harness cannot order the two.

    Excluding the series is right for CVE-2022-0847 - every 5.17 build, rc or
    release, has the fix - and conservative in the rare case where an earlier
    rc would have qualified. A bound with no marker keeps the old reading, so
    a `~beta` build still satisfies "before 1.2.0".
    """
    assert release.upper_bound("Linux Kernel 5.17 rc6", []) == ("5.17~rc", False)
    assert release.upper_bound("5.17-rc6", []) == ("5.17~rc", False)
    assert release.upper_bound("before 1.2.0", []) == ("1.2.0", False)
    assert release.within("5.17~rc8-1~exp1", "5.17~rc", False) is False
    assert release.within("1.2.0~beta2+ds1-1", "1.2.0", False) is True
    # 5.17.1-1~exp1 is a pre-release of 5.17.1, which is past a bound of 5.17.
    assert release.within("5.17.1-1~exp1", "5.17", False) is False


def test_the_ceiling_sweep_says_what_actually_installs() -> None:
    """CVE-2023-0386 picks linux-image-amd64 6.1.190 against a 2023 bound.

    That build did not exist when the advisory was published, and a stable
    series carries backported fixes - so claiming it as the affected version
    is wrong twice. What installs is the serial's build, one day before
    publication, because the setup step installs a package NAME against the
    pinned proxy. The verdict says that rather than naming a version as if it
    had been chosen.
    """
    rel = release.RELEASES[0]
    swept = release.Resolution(
        release=rel, package="linux-image-amd64", prefix="",
        version="6.1.190-1", exact=False,
    )
    said = release.verdict(swept, "before 6.2")
    assert "below 6.2" in said
    assert "shown as 6.1.190-1" in said
    assert "serial one day before the advisory decides" in said
    # A loose prefix match is a different thing and keeps its own warning.
    loose = release.Resolution(
        release=rel, package="apache2", prefix="2.4", version="2.4.58-1", exact=False,
    )
    assert "may carry the fix" in release.verdict(loose, "2.4.49")


def test_the_ceiling_sweep_does_not_match_a_different_product() -> None:
    """A regression this sweep introduced, found by running two CVEs.

    Package names collide across a decade. Debian's `grafana` is 2.6.0 and
    CVE-2021-43798 is about Grafana 8.0.0 to 8.3.0; Debian's `jenkins` is
    1.565.3 from 2014 and CVE-2024-23897 is about 2.441. Both are "below the
    ceiling", so the sweep turned two correct refusals into jobs against
    unrelated software - a false POSITIVE, which is the one direction a
    reproduction lab must not fail in.

    Two guards, because the two cases differ: grafana's range names a floor
    (>= 8.0.0) and jenkins' names one version with no floor at all, so the
    sweep also requires the same major as the ceiling.
    """
    archive = FakeArchive(
        {
            ("grafana", "sid"): ["2.6.0+dfsg-3+b1"],
            ("jenkins", "sid"): ["1.565.3-6"],
            ("linux-image-amd64", "sid"): ["6.7.12-1", "5.16.18-1", "3.16.59-1"],
        }
    )
    assert (
        release.resolve(
            ["grafana"], ">= 8.0.0, < 8.0.7; = 8.3.0", ALL, archive
        )
        is None
    )
    assert release.resolve(["jenkins"], "2.441 and earlier", ALL, archive) is None

    # And the cases the sweep exists for still resolve: a floor the candidate
    # clears, and a single-token range in the candidate's own major.
    wide = release.resolve(
        ["linux-image-amd64"], "3.15 to less than 6.8", ALL, archive, ["6.8"]
    )
    assert wide is not None and wide.version == "6.7.12-1"
    rc = release.resolve(["linux-image-amd64"], "Linux Kernel 5.17 rc6", ALL, archive)
    assert rc is not None and rc.version == "5.16.18-1"


def test_the_records_own_words_for_an_exclusive_bound() -> None:
    """"3.15 to less than 6.8" was read as INCLUSIVE.

    CVE-2024-1086 reads that way and the flattened CNA field it comes from is
    literally `versions[0].lessThan`, so both spellings have to count - and
    without them 6.8.9, which carries the fix, satisfied the bound. Found by a
    rehearsal that passed fixed_versions the first time and so masked it.
    """
    for text in (
        "3.15 to less than 6.8",
        "versions[0].lessThan: 6.8",
        "3.15 up to but not including 6.8",
    ):
        assert release.upper_bound(text, []) == ("6.8", False), text
    assert release.upper_bound("lower than 2.4.51", []) == ("2.4.51", False)
    # And the inclusive readings are unchanged.
    assert release.upper_bound("3.2.1 and below", []) == ("3.2.1", True)
    assert release.upper_bound("2.0.0 - 2.1.3", []) == ("2.1.3", True)
    assert release.upper_bound("2.4.49", []) == ("2.4.49", True)
