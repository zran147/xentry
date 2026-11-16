"""Byte-exact storage for the sources a link check approved."""

# The check fetches the CVE page and the PoC, hashes them into a bundle digest,
# and the job run has to use those same bytes. Re-fetching cannot establish
# that: a page served through a CDN embeds per-request data - a Cloudflare ray
# id, an analytics beacon token - so a second fetch of unchanged content hashes
# differently and the digests never agree. NVD does exactly this, which failed
# every job with source_unavailable. Storing the bytes at check time closes the
# window between check and run instead of detecting it, and takes the network
# off the job's critical path.

from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

from xentry.fetch import Fetched, artifact_text

# Stored sources are a few kilobytes per check. Keep them well past the 30
# minute check expiry so a retried attempt still finds its own bytes, and prune
# by age so the directory cannot grow without bound.
RETENTION_S = 7 * 24 * 3600
_FIELDS = ("url", "final_url", "status", "headers", "sha256")


class SourceStoreError(RuntimeError):
    """Stored sources are absent, unreadable, or fail their digest check."""


def _check_dir(root: Path, check_id: str) -> Path:
    # check_id arrives in a request body and must not name a path outside the
    # store.
    if not check_id or not check_id.isalnum():
        raise SourceStoreError(f"invalid check id: {check_id!r}")
    return root / "checks" / check_id


def save(root: Path, check_id: str, items: dict[str, Fetched]) -> None:
    # The insertion order of `items` is recorded and replayed by load(),
    # because the bundle digest is computed over a list.
    target = _check_dir(root, check_id)
    target.mkdir(parents=True, exist_ok=True)
    entries = {}
    for name, fetched in items.items():
        if not name.isalnum():
            raise SourceStoreError(f"invalid item name: {name!r}")
        (target / f"{name}.body").write_bytes(fetched.body)
        entries[name] = {field: getattr(fetched, field) for field in _FIELDS}
    meta = json.dumps({"order": list(items), "items": entries}, sort_keys=True)
    (target / "meta.json").write_text(meta, encoding="utf-8")


def save_facts(root: Path, check_id: str, payload: str) -> None:
    """The facts the check ADMITTED, beside the bytes they came from.

    The bundle digest guarantees the job sees the same artifacts; nothing
    guaranteed it would read the same facts out of them. Job f062e5c1 refused
    CVE-2021-41773 at step 2 with a refusal its own check had not made, on
    byte-identical cve, poc and nvd artifacts: the reply had poc_command on one
    pass and null on the other. temperature=0 is not a determinism guarantee
    from any provider, so the plan the operator approved has to be the plan
    that runs rather than one re-derived at submit.
    """
    target = _check_dir(root, check_id)
    target.mkdir(parents=True, exist_ok=True)
    (target / "facts.json").write_text(payload, encoding="utf-8")


def save_resolution(root: Path, check_id: str, payload: str) -> None:
    """Which release answered, beside the facts that asked.

    The facts say what to install; this says where it came from - the release,
    the package apt resolved, and the version prefix readiness asserts.

    A job computes it by asking every built release's DATED index, which is a
    network round trip per release and can refuse outright, so a rebuild must
    not redo it: an environment exists to stand the same lab back up, and
    re-resolving months later could pick a different suite than the run being
    reproduced - or fail on an archive that has moved on.
    """
    target = _check_dir(root, check_id)
    target.mkdir(parents=True, exist_ok=True)
    (target / "resolution.json").write_text(payload, encoding="utf-8")


def load_resolution(root: Path, check_id: str) -> str:
    """The stored resolution, or "" when none was recorded or it has aged out."""
    try:
        return (_check_dir(root, check_id) / "resolution.json").read_text(encoding="utf-8")
    except OSError:
        return ""


def load_facts(root: Path, check_id: str) -> str:
    """The stored facts, or "" when this check predates them."""
    try:
        return (_check_dir(root, check_id) / "facts.json").read_text(encoding="utf-8")
    except OSError:
        return ""


def add(root: Path, check_id: str, name: str, fetched: Fetched) -> None:
    """Add one item to a check that was already stored.

    An approved download joins the sources the check already holds, which
    binds it to that check and so to the one job that consumes it: the
    approval cannot leak to the next job, and the retention sweep that already
    prunes checks prunes it too. Nothing else has to learn about it.
    """
    target = _check_dir(root, check_id)
    if not (target / "meta.json").exists():
        raise SourceStoreError(f"no stored sources for check {check_id}")
    if not name.isalnum():
        raise SourceStoreError(f"invalid item name: {name!r}")
    meta = json.loads((target / "meta.json").read_text(encoding="utf-8"))
    (target / f"{name}.body").write_bytes(fetched.body)
    meta["items"][name] = {field: getattr(fetched, field) for field in _FIELDS}
    # Not appended to "order": the bundle digest is computed over the sources
    # the check approved, and adding to it afterwards would change a digest a
    # job has already been told to expect.
    (target / "meta.json").write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")


def drop(root: Path, check_id: str, prefix: str) -> int:
    """Forget every item whose name starts with prefix; return how many.

    An approval is of a SET of bytes, so replacing one has to replace all of
    it. Approving three files and then re-approving one left the other two
    behind - stored under artifact1 and artifact2, which nothing overwrote -
    and the job installed three files, two of them from an approval the
    operator thought they had replaced.
    """
    target = _check_dir(root, check_id)
    if not (target / "meta.json").exists():
        raise SourceStoreError(f"no stored sources for check {check_id}")
    if not prefix.isalnum():
        raise SourceStoreError(f"invalid prefix: {prefix!r}")
    meta = json.loads((target / "meta.json").read_text(encoding="utf-8"))
    gone = [name for name in meta["items"] if name.startswith(prefix)]
    for name in gone:
        (target / f"{name}.body").unlink(missing_ok=True)
        del meta["items"][name]
    (target / "meta.json").write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")
    return len(gone)


def load(root: Path, check_id: str) -> dict[str, Fetched]:
    # Raises rather than returning partial data, so the caller can fall back to
    # a re-fetch instead of running on sources it cannot vouch for.
    target = _check_dir(root, check_id)
    try:
        meta = json.loads((target / "meta.json").read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SourceStoreError(f"no stored sources for check {check_id}") from exc
    except (OSError, ValueError) as exc:
        raise SourceStoreError(f"unreadable store for check {check_id}: {exc}") from exc
    order = meta.get("order")
    if not isinstance(order, list):
        raise SourceStoreError(f"malformed store for check {check_id}")
    entries = meta.get("items")
    if not isinstance(entries, dict):
        raise SourceStoreError(f"malformed store for check {check_id}")
    restored: dict[str, Fetched] = {}
    # The ordered sources first, because the bundle digest is computed over
    # that list, then anything added afterwards.
    for name in [*order, *(name for name in sorted(entries) if name not in order)]:
        try:
            entry = entries[name]
            body = (target / f"{name}.body").read_bytes()
            digest = hashlib.sha256(body).hexdigest()
            if digest != entry["sha256"]:
                raise SourceStoreError(f"stored body for {name!r} does not match its digest")
            fields = {field: entry[field] for field in _FIELDS}
            restored[name] = Fetched(
                body=body,
                # Rendered the way fetch() renders it, from the headers stored
                # alongside the bytes. A plain decode here is not a smaller
                # version of the same thing: it is what every reader downstream
                # sees, so the advisory arrives as one line of JSON with no
                # citable lines and no date anything can find.
                text=artifact_text(dict(fields["headers"]), body),
                **fields,
            )
        except (KeyError, OSError, TypeError, ValueError) as exc:
            raise SourceStoreError(f"bad stored source {name!r}: {exc}") from exc
    return restored


def prune(root: Path, *, retention_s: float = RETENTION_S) -> int:
    # Age, not check state, decides what goes: a check is marked used the moment
    # a job claims it, but that job may still be running or about to retry, and
    # it needs its bytes. glob on a missing directory yields nothing, and a
    # per-entry guard keeps a vanished directory from failing the request this
    # runs in.
    cutoff = time.time() - retention_s
    removed = 0
    for path in (root / "checks").glob("*"):
        try:
            stale = path.stat().st_mtime < cutoff
        except OSError:
            continue
        if stale:
            shutil.rmtree(path, ignore_errors=True)
            removed += 1
    return removed
