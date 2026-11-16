"""The date-pinned registry mirror.

What it has to get right is the same thing the apt mirror does: serve exactly
one upstream, over a path shape fixed in the source, at a date the guest
cannot choose - and refuse everything else.
"""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from broker.registryproxy import (
    ECOSYSTEMS,
    RegistryPathRefused,
    RegistryProxy,
    RegistryProxyError,
    check_cutoff,
)

CUTOFF = "2026-10-10T00:00:00Z"
PACKUMENT = {
    "name": "next",
    "dist-tags": {"latest": "16.4.1"},
    "time": {
        "16.4.0": "2026-10-06T18:35:31.699Z",
        "16.4.1": "2026-10-14T17:43:55.246Z",
        "16.3.0": "2026-09-01T00:00:00.000Z",
    },
    "versions": {
        "16.3.0": {"name": "next", "version": "16.3.0", "dist": {"tarball": "https://registry.npmjs.org/next/-/next-16.3.0.tgz", "integrity": "sha512-old"}},
        "16.4.0": {
            "name": "next",
            "version": "16.4.0",
            "bin": {"next": "dist/bin/next"},
            "engines": {"node": ">=20.9.0"},
            "scripts": {"postinstall": "node ./scripts/post.js"},
            "readme": "x" * 4000,
            "_npmUser": {"name": "vercel"},
            "dist": {"tarball": "https://registry.npmjs.org/next/-/next-16.4.0.tgz", "integrity": "sha512-abc"},
        },
        "16.4.1": {"name": "next", "version": "16.4.1", "dist": {"tarball": "https://registry.npmjs.org/next/-/next-16.4.1.tgz", "integrity": "sha512-fix"}},
    },
}
SIMPLE = {
    "meta": {"api-version": "1.1"},
    "name": "requests",
    "versions": ["2.31.0", "2.32.0"],
    "files": [
        {
            "filename": "requests-2.31.0-py3-none-any.whl",
            "url": "https://files.pythonhosted.org/packages/aa/bb/requests-2.31.0-py3-none-any.whl",
            "hashes": {"sha256": "a" * 64},
            "upload-time": "2023-05-22T15:12:42.123456Z",
        },
        {
            "filename": "requests-2.32.0-py3-none-any.whl",
            "url": "https://files.pythonhosted.org/packages/cc/dd/requests-2.32.0-py3-none-any.whl",
            "hashes": {"sha256": "b" * 64},
            "upload-time": "2026-11-01T00:00:00.000000Z",
        },
    ],
}


class FakeUpstream:
    """Stands in for the registry; records every request the host makes."""

    def __init__(self, bodies: dict[str, bytes]) -> None:
        self.bodies = bodies
        self.asked: list[str] = []

    def open(self, request: Any, timeout: float = 0) -> Any:
        url = request.full_url
        self.asked.append(url)
        body = self.bodies.get(url)
        if body is None:
            raise urllib.error.HTTPError(url, 404, "not found", {}, None)  # type: ignore[arg-type]

        class Response:
            def read(self) -> bytes:
                return body

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

        return Response()


def _proxy(tmp_path: Path, bodies: dict[str, bytes], cutoff: str = CUTOFF) -> tuple[RegistryProxy, FakeUpstream]:
    upstream = FakeUpstream(bodies)
    proxy = RegistryProxy(
        tmp_path / "cache", bind="10.42.1.1", port=8083, cutoff=cutoff, opener=upstream  # type: ignore[arg-type]
    )
    return proxy, upstream


def test_an_index_holds_only_what_existed_before_the_cutoff(tmp_path: Path) -> None:
    """The whole mechanism: a snapshot the registry does not publish."""
    proxy, _ = _proxy(tmp_path, {"https://registry.npmjs.org/next": json.dumps(PACKUMENT).encode()})
    document = json.loads(proxy.index("npm", "next"))
    assert sorted(document["versions"]) == ["16.3.0", "16.4.0"]
    assert document["dist-tags"]["latest"] == "16.4.0"


def test_the_fix_is_what_the_cutoff_removes(tmp_path: Path) -> None:
    """16.4.1 exists upstream and must not be offered: resolving against a
    live registry is how a job installs the patched build by accident."""
    proxy, _ = _proxy(tmp_path, {"https://registry.npmjs.org/next": json.dumps(PACKUMENT).encode()})
    assert "16.4.1" not in json.loads(proxy.index("npm", "next"))["versions"]


def test_a_tarball_url_keeps_upstreams_own_path_shape(tmp_path: Path) -> None:
    """Not cosmetic. With a lockfile in the tree npm ignores dist.tarball and
    rewrites each `resolved` onto the configured registry as
    <registry>/<name>/-/<file>, so a proxy with a prefix of its own invention
    answers 403 to a request npm was always going to make."""
    proxy, _ = _proxy(tmp_path, {"https://registry.npmjs.org/next": json.dumps(PACKUMENT).encode()})
    entry = json.loads(proxy.index("npm", "next"))["versions"]["16.4.0"]
    assert entry["dist"]["tarball"] == "http://10.42.1.1:8083/npm/next/-/next-16.4.0.tgz"
    # The integrity is untouched, which is why the guest does not have to
    # trust this proxy: npm checks the bytes against it.
    assert entry["dist"]["integrity"] == "sha512-abc"


def test_resolution_metadata_survives_and_prose_does_not(tmp_path: Path) -> None:
    """Dropping `bin` would install next with no next command and fail the
    build with nothing to point at; carrying every readme would multiply the
    index a guest has to download."""
    proxy, _ = _proxy(tmp_path, {"https://registry.npmjs.org/next": json.dumps(PACKUMENT).encode()})
    entry = json.loads(proxy.index("npm", "next"))["versions"]["16.4.0"]
    assert entry["bin"] == {"next": "dist/bin/next"}
    assert entry["engines"] == {"node": ">=20.9.0"}
    assert entry["hasInstallScript"] is True
    assert "readme" not in entry
    assert "_npmUser" not in entry


def test_a_version_served_from_elsewhere_is_dropped(tmp_path: Path) -> None:
    """The guest must only ever reach the one upstream named in this file."""
    odd = json.loads(json.dumps(PACKUMENT))
    odd["versions"]["16.4.0"]["dist"]["tarball"] = "https://evil.example/next-16.4.0.tgz"
    proxy, _ = _proxy(tmp_path, {"https://registry.npmjs.org/next": json.dumps(odd).encode()})
    assert "16.4.0" not in json.loads(proxy.index("npm", "next"))["versions"]


def test_a_pypi_index_filters_by_upload_time(tmp_path: Path) -> None:
    proxy, _ = _proxy(tmp_path, {"https://pypi.org/simple/requests/": json.dumps(SIMPLE).encode()})
    document = json.loads(proxy.index("pypi", "requests"))
    assert [item["filename"] for item in document["files"]] == [
        "requests-2.31.0-py3-none-any.whl"
    ]
    assert document["files"][0]["url"].startswith("http://10.42.1.1:8083/pypi/packages/")
    assert document["files"][0]["hashes"]["sha256"] == "a" * 64


def test_pip_is_served_the_content_type_it_will_read(tmp_path: Path) -> None:
    """pip names the three types it accepts and skips the page otherwise,
    which reads as "no matching distribution found"."""
    assert ECOSYSTEMS["pypi"].index_type == "application/vnd.pypi.simple.v1+json"
    proxy, _ = _proxy(tmp_path, {"https://pypi.org/simple/requests/": json.dumps(SIMPLE).encode()})
    _, _, content_type = proxy.route("/pypi/requests/")
    assert content_type == "application/vnd.pypi.simple.v1+json"


def test_the_index_is_cached_unfiltered_so_another_date_is_free(tmp_path: Path) -> None:
    """The cache is shared across jobs and CVEs, which a per-lab closure was
    not: a second job at another date asks upstream for nothing."""
    bodies = {"https://registry.npmjs.org/next": json.dumps(PACKUMENT).encode()}
    first, upstream = _proxy(tmp_path, bodies)
    first.index("npm", "next")
    assert len(upstream.asked) == 1
    second = RegistryProxy(
        tmp_path / "cache", bind="10.42.1.1", port=8083,
        cutoff="2026-09-02T00:00:00Z", opener=upstream,  # type: ignore[arg-type]
    )
    assert sorted(json.loads(second.index("npm", "next"))["versions"]) == ["16.3.0"]
    assert len(upstream.asked) == 1, "a cached index was re-fetched"


@pytest.mark.parametrize(
    "path",
    [
        "/npm/../etc/passwd",
        "/pypi/etc/passwd",
        "/nodejs/latest/node.tar.xz",
        "/evil/next",
        "/npm",
        "/npm/",
        "/npm/UPPERCASE",
        "/npm/next/-/next-16.4.0.tgz/../../x",
    ],
)
def test_a_path_outside_the_shape_is_refused(tmp_path: Path, path: str) -> None:
    proxy, upstream = _proxy(tmp_path, {})
    with pytest.raises(RegistryPathRefused):
        proxy.route(path)
    assert upstream.asked == [], "a refused path still reached upstream"


def test_a_runtime_is_fetched_by_exact_version(tmp_path: Path) -> None:
    url = "https://nodejs.org/dist/v22.11.0/node-v22.11.0-linux-x64.tar.xz"
    proxy, _ = _proxy(tmp_path, {url: b"tarball-bytes"})
    _, local, content_type = proxy.route("/nodejs/v22.11.0/node-v22.11.0-linux-x64.tar.xz")
    assert local is not None and local.read_bytes() == b"tarball-bytes"
    assert content_type == "application/octet-stream"


def test_a_cutoff_has_to_be_a_timestamp() -> None:
    assert check_cutoff(CUTOFF) == CUTOFF
    for bad in ("2026-10-10", "yesterday", "", "2026-10-10T00:00:00Z; rm -rf /"):
        with pytest.raises(RegistryProxyError):
            check_cutoff(bad)


def test_an_upstream_failure_is_reported_not_cached(tmp_path: Path) -> None:
    proxy, upstream = _proxy(tmp_path, {})
    with pytest.raises(RegistryProxyError, match="upstream 404"):
        proxy.index("npm", "nope")
    assert not (tmp_path / "cache" / "npm" / "nope.json").exists()
    with pytest.raises(RegistryProxyError):
        proxy.blob("nodejs", "v1.2.3/node-v1.2.3-linux-x64.tar.xz")
    assert len(upstream.asked) == 2


def test_npms_own_lockfile_url_shape_is_served(tmp_path: Path) -> None:
    """The bug this file's path shapes exist for.

    npm asked for /npm/colorette/-/colorette-2.0.20.tgz and got 403, because
    the proxy had invented a /npm/-/ prefix that npm never uses.
    """
    url = "https://registry.npmjs.org/colorette/-/colorette-2.0.20.tgz"
    proxy, _ = _proxy(tmp_path, {url: b"tgz"})
    _, local, _ = proxy.route("/npm/colorette/-/colorette-2.0.20.tgz")
    assert local is not None and local.read_bytes() == b"tgz"


def test_a_scoped_tarball_is_served_under_either_spelling(tmp_path: Path) -> None:
    url = "https://registry.npmjs.org/@next/env/-/env-16.4.0.tgz"
    proxy, _ = _proxy(tmp_path, {url: b"scoped"})
    for path in ("/npm/@next/env/-/env-16.4.0.tgz", "/npm/%40next%2Fenv/-/env-16.4.0.tgz"):
        _, local, _ = proxy.route(path)
        assert local is not None and local.read_bytes() == b"scoped", path


def test_a_prerelease_is_never_the_latest_tag(tmp_path: Path) -> None:
    """`next` always has a canary with a higher number than its newest
    release, so a bare install would have taken one."""
    document = json.loads(json.dumps(PACKUMENT))
    document["time"]["16.5.0-canary.0"] = "2026-10-07T00:00:00.000Z"
    document["versions"]["16.5.0-canary.0"] = {
        "name": "next",
        "version": "16.5.0-canary.0",
        "dist": {"tarball": "https://registry.npmjs.org/next/-/next-16.5.0-canary.0.tgz"},
    }
    document["dist-tags"] = {"latest": "16.4.1"}
    proxy, _ = _proxy(tmp_path, {"https://registry.npmjs.org/next": json.dumps(document).encode()})
    served = json.loads(proxy.index("npm", "next"))
    assert "16.5.0-canary.0" in served["versions"]
    assert served["dist-tags"]["latest"] == "16.4.0"


def test_an_index_older_than_the_cutoff_is_refetched(tmp_path: Path) -> None:
    """The cache answers any date before it was fetched, and no date after.

    Serving a stale index to a job with a newer cutoff would quietly say that
    every release since the fetch does not exist, and the job would resolve to
    an older version with nothing in the record to explain it.
    """
    import os
    import time

    bodies = {"https://registry.npmjs.org/next": json.dumps(PACKUMENT).encode()}
    proxy, upstream = _proxy(tmp_path, bodies, cutoff="2026-10-10T00:00:00Z")
    proxy.index("npm", "next")
    assert len(upstream.asked) == 1
    cached = tmp_path / "cache" / "npm" / "next.json"
    # Backdate the cache to before the cutoff it is about to be asked for.
    old = time.time() - 400 * 24 * 3600
    os.utime(cached, (old, old))
    proxy.index("npm", "next")
    assert len(upstream.asked) == 2, "a stale index was served for a later cutoff"
    # And once it is fresh again, it is reused.
    proxy.index("npm", "next")
    assert len(upstream.asked) == 2


def test_the_runtime_url_the_setup_step_builds_is_one_this_proxy_routes() -> None:
    """Three files have to agree on one path, and for a while two did.

    The index rewrites moved to upstream's own path shape; the hand-written
    curl in setup-npm.sh kept an invented `-/` prefix, so the proxy would have
    answered 403 to the very first thing every ecosystem job does.
    """
    from xentry.ecosystem import NODE_VERSION

    script = (ROOT / "targets" / "common" / "setup-npm.sh").read_text()
    assert '"${registry}nodejs/${node_version}/${tarball}"' in script
    assert 'tarball="node-${node_version}-linux-x64.tar.xz"' in script
    built = f"{NODE_VERSION}/node-{NODE_VERSION}-linux-x64.tar.xz"
    assert ECOSYSTEMS["nodejs"].blob_re.match(built), built


ROOT = Path(__file__).resolve().parents[1]


def test_a_truncated_index_is_not_cached_and_the_retry_recovers(tmp_path: Path) -> None:
    """A 200 with a short body is the case the 404 test does not cover.

    The cache was written straight off the socket, before anything parsed it,
    so one reply cut mid-body - a reset, a proxy trimming the response - was
    stored and then reused for every later job at the same cutoff. Upstream
    was asked once, and every attempt after that failed with "index for next
    is not JSON", which blames npm for a file of ours. The only recovery was
    deleting the cache file by hand.
    """
    url = "https://registry.npmjs.org/next"
    proxy, upstream = _proxy(tmp_path, {url: b'{"name":"next","versions":{"16.4.0":{"vers'})
    cached = tmp_path / "cache" / "npm" / "next.json"

    with pytest.raises(RegistryProxyError, match="not JSON"):
        proxy.index("npm", "next")
    assert not cached.exists(), "a body that does not parse was cached"

    # The same proxy, the same cutoff: upstream is asked again rather than the
    # bad answer being replayed.
    upstream.bodies[url] = json.dumps(PACKUMENT).encode()
    document = json.loads(proxy.index("npm", "next"))
    assert sorted(document["versions"]) == ["16.3.0", "16.4.0"]
    assert len(upstream.asked) == 2, upstream.asked
    assert cached.exists()

    # And now it is cached, so a third call costs nothing.
    json.loads(proxy.index("npm", "next"))
    assert len(upstream.asked) == 2, upstream.asked


def test_an_index_that_is_not_an_object_is_not_cached_either(tmp_path: Path) -> None:
    url = "https://registry.npmjs.org/next"
    proxy, _upstream = _proxy(tmp_path, {url: b'["next"]'})
    with pytest.raises(RegistryProxyError, match="not an object"):
        proxy.index("npm", "next")
    assert not (tmp_path / "cache" / "npm" / "next.json").exists()
