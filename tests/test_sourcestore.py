"""The checked sources are stored byte-exact and reused by the job run.

Re-fetching cannot establish that sources are unchanged: a page served
through a CDN embeds per-request data, so a second fetch of identical content
hashes differently. These tests pin that the store, not a re-fetch, is what
the bundle digest is compared against.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from xentry.fetch import Fetched, artifact_text, bundle_sha256
from xentry.sourcestore import SourceStoreError, load, prune, save


def _fetched(url: str, body: bytes, content_type: str = "text/html") -> Fetched:
    """A Fetched the way fetch() builds one, which is the point.

    This helper used to decode the body for `text`, the same mistake the store
    itself had, so the round-trip test asserted the bug rather than catching
    it. `text` is a rendering of the body and the store has to reproduce it.
    """
    headers = {"content-type": content_type}
    return Fetched(
        url=url,
        final_url=url,
        status=200,
        headers=headers,
        body=body,
        text=artifact_text(headers, body),
        sha256=hashlib.sha256(body).hexdigest(),
    )


def _pair(cve_body: bytes) -> dict[str, Fetched]:
    return {
        "cve": _fetched("https://nvd.nist.gov/vuln/detail/CVE-1", cve_body),
        "poc": _fetched("https://raw.githubusercontent.com/o/r/c/README.md", b"# poc"),
    }


def test_round_trip_preserves_every_field(tmp_path: Path) -> None:
    items = _pair(b"<html>cve</html>")
    save(tmp_path, "abc123", items)
    restored = load(tmp_path, "abc123")

    assert list(restored) == ["cve", "poc"]
    for name, original in items.items():
        assert restored[name].url == original.url
        assert restored[name].final_url == original.final_url
        assert restored[name].status == original.status
        assert restored[name].headers == original.headers
        assert restored[name].body == original.body
        assert restored[name].text == original.text
        assert restored[name].sha256 == original.sha256


def test_bundle_digest_survives_an_unstable_page(tmp_path: Path) -> None:
    # The regression: the same CVE page fetched twice differs, because the CDN
    # injects a per-request id. The digest from the store must still match the
    # one the check recorded.
    first = _pair(b"<html>cve ray=aaaa1111</html>")
    second = _pair(b"<html>cve ray=bbbb2222</html>")
    at_check = bundle_sha256([first["cve"], first["poc"]])
    on_refetch = bundle_sha256([second["cve"], second["poc"]])
    assert at_check != on_refetch, "fixture must model an unstable page"

    save(tmp_path, "unstable", first)
    restored = load(tmp_path, "unstable")
    assert bundle_sha256([restored["cve"], restored["poc"]]) == at_check


def test_order_is_preserved_because_the_digest_is_over_a_list(tmp_path: Path) -> None:
    items = _pair(b"cve")
    save(tmp_path, "ordered", items)
    assert list(load(tmp_path, "ordered")) == list(items)


def test_altered_body_is_refused(tmp_path: Path) -> None:
    save(tmp_path, "tampered", _pair(b"original"))
    (tmp_path / "checks" / "tampered" / "cve.body").write_bytes(b"swapped")
    with pytest.raises(SourceStoreError, match="does not match its digest"):
        load(tmp_path, "tampered")


def test_truncated_metadata_is_refused(tmp_path: Path) -> None:
    save(tmp_path, "broken", _pair(b"cve"))
    (tmp_path / "checks" / "broken" / "meta.json").write_text("{not json")
    with pytest.raises(SourceStoreError):
        load(tmp_path, "broken")


def test_malformed_metadata_is_refused(tmp_path: Path) -> None:
    save(tmp_path, "shaped", _pair(b"cve"))
    path = tmp_path / "checks" / "shaped" / "meta.json"
    path.write_text(json.dumps({"order": "cve", "items": {}}))
    with pytest.raises(SourceStoreError, match="malformed"):
        load(tmp_path, "shaped")


def test_missing_check_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SourceStoreError, match="no stored sources"):
        load(tmp_path, "absent")


@pytest.mark.parametrize("check_id", ["../escape", "a/b", "", "with space", "a.b"])
def test_check_id_cannot_leave_the_store(tmp_path: Path, check_id: str) -> None:
    # check_id arrives in a request body.
    with pytest.raises(SourceStoreError, match="invalid check id"):
        load(tmp_path, check_id)
    with pytest.raises(SourceStoreError, match="invalid check id"):
        save(tmp_path, check_id, _pair(b"cve"))


def test_prune_drops_old_and_keeps_recent(tmp_path: Path) -> None:
    save(tmp_path, "old", _pair(b"cve"))
    save(tmp_path, "fresh", _pair(b"cve"))
    old = tmp_path / "checks" / "old"
    os.utime(old, (0, time.time() - 10 * 24 * 3600))

    assert prune(tmp_path) == 1
    assert not old.exists()
    assert (tmp_path / "checks" / "fresh").exists()
    # A retried attempt must still find bytes for a check already marked used,
    # which is why age and not check state decides.
    assert load(tmp_path, "fresh")


def test_prune_on_an_empty_store_is_a_no_op(tmp_path: Path) -> None:
    assert prune(tmp_path) == 0


def test_the_store_replays_the_rendering_a_live_fetch_would_have_given(
    tmp_path: Path,
) -> None:
    """The regression, and it was silent on every real job.

    A link check stores the bytes; the job reads `text`. The store rebuilt
    `text` as a plain decode, so the advisory reached the extractor as one
    line of JSON - no citable lines, and no publication date that
    advisory_published could find. The npm target refused outright; the apt
    path quietly lost its snapshot serial and provisioned from the broker's
    default, which for a recent CVE is usually the patched build.
    """
    from xentry import generic

    record = json.dumps(
        {"cveMetadata": {"cveId": "CVE-2026-1", "datePublished": "2026-06-29T14:31:37.952Z"}}
    ).encode()
    live = _fetched("https://www.cve.org/CVERecord?id=CVE-2026-1", record, "application/json")
    assert generic.advisory_published(live.text) == "2026-06-29T14:31:37.952Z"

    save(tmp_path, "abc123", {"cve": live, "poc": _fetched("https://x/README.md", b"# poc")})
    replayed = load(tmp_path, "abc123")["cve"]
    assert replayed.text == live.text
    assert generic.advisory_published(replayed.text) == "2026-06-29T14:31:37.952Z"
    assert generic.cutoff_for(generic.advisory_published(replayed.text)) == "2026-06-28T00:00:00Z"
