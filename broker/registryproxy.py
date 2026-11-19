"""Date-pinned reverse proxy for application package registries.

`snapshot.ubuntu.com` is why the apt mirror works: Ubuntu publishes an
immutable snapshot of the whole archive at a serial, so `apt-get install
apache2` against that serial resolves the same way forever. No application
registry publishes anything like it, which is why entry 15b resolved npm
closures on the host instead and said there would be no registry proxy.

That was wrong, and measurement said so. Every registry publishes a
*timestamp* per release - npm a `time` map in the packument, PyPI an
`upload-time` per file - so a proxy can synthesise the snapshot that upstream
does not offer: it serves an index holding only what existed before the
advisory was published, and the client resolves deterministically with no
lockfile, no closure and no flag of its own.

It is better than pinning a closure, not merely cheaper. A closure resolved on
the host takes today's answer to the version ranges a lab declares, and for a
recent CVE today's answer leans toward the fix: resolving the briskets lab
that way pins react 19.3.1, while the same lab through this proxy at the
advisory's date pins 19.3.0. The apt side has always provisioned from just
before the advisory. This is the same rule for everything else.

Like the apt mirror this is a reverse proxy, not a forward one. The guest's
registry setting points here; the upstream and the path shape are fixed in
this file; no destination, header or host is ever read out of a request. There
is no CONNECT and nothing a guest can aim elsewhere.

The index cache holds the unfiltered upstream document, so a second job filters
the same bytes at its own cutoff and asks upstream nothing: the cache is shared
across every job and every CVE, which a per-lab closure never was.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass

# timezone.utc, not datetime.UTC: UTC was added in Python 3.11 and this
# module is copied into the proxy VM, which runs the base image's
# python - 3.9 on Debian 11. The import failed there and took the whole
# mirror service down:
#   ImportError: cannot import name 'UTC' from 'datetime'
# timezone.utc means the same thing and works on every version.
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

UPSTREAM_TIMEOUT_S = 120
STAMP = "%Y-%m-%dT%H:%M:%SZ"
CUTOFF_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$")
# An npm package name, scoped or not, as npm itself allows it.
NPM_NAME_RE = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
# A PyPI project name normalised per PEP 503.
PYPI_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")
# Blob paths: what a rewritten index can point back at, and nothing else.
NPM_BLOB_RE = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*/-/[A-Za-z0-9._-]+\.tgz$")
PYPI_BLOB_RE = re.compile(r"^packages/[A-Za-z0-9/._-]+$")
NODE_BLOB_RE = re.compile(r"^v\d+\.\d+\.\d+/[A-Za-z0-9._-]+$")
# Every ecosystem's blob path must be unmistakably a blob: an index request can
# never match one, or a package would be served as a file.

# The abbreviated-packument fields. Dropping `bin` here would install `next`
# with no `next` command and fail the build with nothing to point at.
NPM_VERSION_FIELDS = frozenset(
    {
        "name", "version", "dependencies", "peerDependencies", "peerDependenciesMeta",
        "optionalDependencies", "bundleDependencies", "acceptDependencies", "bin",
        "directories", "dist", "engines", "deprecated", "funding", "os", "cpu", "libc",
        "_hasShrinkwrap",
    }
)
INSTALL_HOOKS = ("preinstall", "install", "postinstall")


class RegistryProxyError(RuntimeError):
    """The registry proxy could not start or serve."""


class RegistryPathRefused(RegistryProxyError):
    """The request was not one this proxy will make."""


def check_cutoff(cutoff: str) -> str:
    if not CUTOFF_RE.match(cutoff):
        raise RegistryProxyError(f"invalid registry cutoff: {cutoff!r}")
    return cutoff


@dataclass(frozen=True)
class Ecosystem:
    """One upstream, its two path shapes, and how to date-filter its index."""

    name: str
    index_host: str
    index_path: str
    # pip refuses an index served as application/json and names the three
    # types it will read, so the content type is part of the contract, not a
    # detail: getting it wrong looks like "no matching distribution found".
    index_type: str
    blob_host: str
    blob_prefix: str
    blob_re: re.Pattern[str]
    name_re: re.Pattern[str] | None


ECOSYSTEMS = {
    item.name: item
    for item in (
        Ecosystem(
            name="npm",
            index_host="registry.npmjs.org",
            index_path="/{name}",
            index_type="application/json",
            blob_host="registry.npmjs.org",
            blob_prefix="",
            blob_re=NPM_BLOB_RE,
            name_re=NPM_NAME_RE,
        ),
        Ecosystem(
            name="pypi",
            index_host="pypi.org",
            index_path="/simple/{name}/",
            index_type="application/vnd.pypi.simple.v1+json",
            blob_host="files.pythonhosted.org",
            blob_prefix="",
            blob_re=PYPI_BLOB_RE,
            name_re=PYPI_NAME_RE,
        ),
        # No index and so no cutoff: a runtime is asked for by exact version,
        # the way the Dirty Frag kernel is. It is here so that an ecosystem
        # target needs no image of its own.
        Ecosystem(
            name="nodejs",
            index_host="",
            index_path="",
            index_type="",
            blob_host="nodejs.org",
            blob_prefix="dist/",
            blob_re=NODE_BLOB_RE,
            name_re=None,
        ),
    )
}


def _filter_npm(document: dict[str, Any], cutoff: str, base: str) -> dict[str, Any]:
    """An abbreviated packument holding only versions published before cutoff."""
    times = document.get("time") or {}
    versions: dict[str, Any] = {}
    for version, entry in (document.get("versions") or {}).items():
        when = str(times.get(version) or "")
        if not when or when >= cutoff or not isinstance(entry, dict):
            continue
        kept = {key: value for key, value in entry.items() if key in NPM_VERSION_FIELDS}
        scripts = entry.get("scripts") or {}
        if isinstance(scripts, dict) and any(hook in scripts for hook in INSTALL_HOOKS):
            kept["hasInstallScript"] = True
        dist = dict(kept.get("dist") or {})
        tarball = str(dist.get("tarball") or "")
        rest = tarball.split(f"//{ECOSYSTEMS['npm'].index_host}/", 1)
        if len(rest) != 2:
            # A version served from somewhere else is dropped rather than
            # proxied: the guest must only ever reach the one upstream here.
            continue
        dist["tarball"] = f"{base}/npm/{rest[1]}"
        kept["dist"] = dist
        versions[version] = kept
    tags = {
        tag: version
        for tag, version in (document.get("dist-tags") or {}).items()
        if version in versions
    }
    if "latest" not in tags and versions:
        tags["latest"] = max(versions, key=_order)
    return {"name": document.get("name"), "dist-tags": tags, "versions": versions}


def _order(version: str) -> tuple[int, list[int]]:
    """Release first, then version numbers.

    The release flag leads, so every release sorts above every prerelease
    rather than only above the prerelease of its own numbers. Ordering the
    other way round made `latest` resolve to a canary whenever one existed
    with a higher number than the newest release - which for `next` it always
    does, and a bare install would have taken it.
    """
    head = version.split("-", 1)[0]
    try:
        parts = [int(piece) for piece in head.split(".")]
    except ValueError:
        return (0, [0])
    return (0 if "-" in version else 1, parts)


def _filter_pypi(document: dict[str, Any], cutoff: str, base: str) -> dict[str, Any]:
    """A PEP 691 index holding only files uploaded before cutoff."""
    files = []
    for entry in document.get("files") or []:
        if not isinstance(entry, dict):
            continue
        when = str(entry.get("upload-time") or "")
        if not when or when >= cutoff:
            continue
        url = str(entry.get("url") or "")
        rest = url.split(f"//{ECOSYSTEMS['pypi'].blob_host}/", 1)
        if len(rest) != 2:
            continue
        files.append({**entry, "url": f"{base}/pypi/{rest[1]}"})
    return {
        "meta": {"api-version": "1.1"},
        "name": document.get("name"),
        "files": files,
        "versions": document.get("versions") or [],
    }


FILTERS = {"npm": _filter_npm, "pypi": _filter_pypi}


def _cache_path(root: Path, *parts: str) -> Path:
    base = root.resolve()
    path = base.joinpath(*parts).resolve()
    if path != base and base not in path.parents:
        raise RegistryProxyError(f"cache path escapes {base}: {parts}")
    return path


class RegistryProxy:
    """One per job. Serves every ecosystem from one port at one cutoff."""

    def __init__(
        self,
        cache_dir: Path,
        *,
        bind: str,
        port: int = 8083,
        cutoff: str,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.bind = bind
        self.port = port
        self.cutoff = check_cutoff(cutoff)
        self.opener = opener or urllib.request.build_opener()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.bind}:{self.port}"

    def _get(self, host: str, path: str, accept: str = "") -> bytes:
        # No guest header is carried upstream and none is added beyond a
        # generic agent: the guest must not shape what the host sends out.
        headers = {"User-Agent": "xentry-registry-mirror"}
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(f"https://{host}{path}", headers=headers)
        try:
            with self.opener.open(request, timeout=UPSTREAM_TIMEOUT_S) as response:
                return bytes(response.read())
        except urllib.error.HTTPError as exc:
            raise RegistryProxyError(f"upstream {exc.code} for {host}{path}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RegistryProxyError(f"upstream unreachable for {host}{path}: {exc}") from exc

    def index(self, ecosystem: str, name: str) -> bytes:
        """The upstream index, date-filtered and pointed back at this proxy."""
        spec = ECOSYSTEMS.get(ecosystem)
        if spec is None or spec.name_re is None or not spec.name_re.match(name):
            raise RegistryPathRefused(f"refused {ecosystem} package: {name!r}")
        cached = _cache_path(self.cache_dir, ecosystem, f"{name.replace('/', '%2f')}.json")
        # A cached index is only usable for a cutoff it was already complete
        # for. The cache never expires on purpose - an index fetched a year
        # ago still answers every question about a date before it - but a job
        # whose cutoff is *newer* than the fetch would silently be told that
        # releases made since then do not exist, and would resolve to an older
        # version with nothing in the record to say why.
        fetched_at = (
            datetime.fromtimestamp(cached.stat().st_mtime, timezone.utc).strftime(STAMP)
            if cached.is_file()
            else ""
        )
        fresh = b""
        if fetched_at and fetched_at > self.cutoff:
            raw = cached.read_bytes()
        else:
            raw = fresh = self._get(
                spec.index_host,
                spec.index_path.format(name=quote(name, safe="@/")),
                spec.index_type,
            )
        try:
            document = json.loads(raw)
        except ValueError as exc:
            raise RegistryProxyError(f"{ecosystem} index for {name} is not JSON") from exc
        if not isinstance(document, dict):
            raise RegistryProxyError(f"{ecosystem} index for {name} is not an object")
        # Written only once it has parsed. The cache was written straight off
        # the socket, so one truncated reply - a reset mid-body, a proxy
        # cutting the response - was stored and then reused for every later
        # job: upstream was asked once, and every attempt after it failed with
        # "index for next is not JSON", which blames npm for a file of ours.
        # Measured; the only recovery was deleting the file by hand.
        if fresh:
            cached.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            partial = cached.with_name(cached.name + ".part")
            partial.write_bytes(fresh)
            partial.chmod(0o640)
            os.replace(partial, cached)
        filtered = FILTERS[ecosystem](document, self.cutoff, self.url)
        return json.dumps(filtered).encode()

    def blob(self, ecosystem: str, rest: str) -> Path:
        """One tarball, wheel or runtime archive, fetched once and cached."""
        spec = ECOSYSTEMS.get(ecosystem)
        if spec is None or ".." in rest or not spec.blob_re.match(rest):
            raise RegistryPathRefused(f"refused {ecosystem} path: {rest!r}")
        cached = _cache_path(self.cache_dir, ecosystem, "-", *rest.split("/"))
        if cached.is_file():
            return cached
        cached.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        partial = cached.with_name(cached.name + ".part")
        try:
            partial.write_bytes(self._get(spec.blob_host, f"/{spec.blob_prefix}{rest}"))
        except RegistryProxyError:
            partial.unlink(missing_ok=True)
            raise
        partial.chmod(0o640)
        os.replace(partial, cached)
        return cached

    def route(self, path: str) -> tuple[bytes | None, Path | None, str]:
        """Resolve one guest request: a blob if it looks like one, else an index.

        The paths are upstream's own, which is not cosmetic. npm does not
        always follow the `dist.tarball` an index gives it - with a lockfile in
        the tree it rewrites each `resolved` onto the configured registry as
        `<registry>/<name>/-/<file>` - so a proxy that invented its own blob
        prefix answered 403 to a request npm was always going to make.
        """
        ecosystem, _, rest = path.lstrip("/").partition("/")
        spec = ECOSYSTEMS.get(ecosystem)
        if spec is None or not rest:
            raise RegistryPathRefused(f"refused path: {path}")
        rest = unquote(rest)
        if spec.blob_re.match(rest):
            return None, self.blob(ecosystem, rest), "application/octet-stream"
        return self.index(ecosystem, rest.rstrip("/")), None, spec.index_type

    def start(self) -> None:
        if self._server is not None:
            return
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _serve(self, body: bool) -> None:
                try:
                    payload, local, content_type = proxy.route(urlsplit(self.path).path)
                except RegistryPathRefused as exc:
                    self.send_error(403, str(exc))
                    return
                except RegistryProxyError as exc:
                    self.send_error(404 if "upstream 404" in str(exc) else 502, str(exc))
                    return
                size = len(payload) if payload is not None else local.stat().st_size  # type: ignore[union-attr]
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(size))
                self.end_headers()
                if not body:
                    return
                if payload is not None:
                    self.wfile.write(payload)
                elif local is not None:
                    with local.open("rb") as handle:
                        shutil.copyfileobj(handle, self.wfile)

            def do_GET(self) -> None:
                self._serve(True)

            def do_HEAD(self) -> None:
                self._serve(False)

            def log_message(self, *args: object) -> None:
                return

        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
            self._server = ThreadingHTTPServer((self.bind, self.port), Handler)
        except OSError as exc:
            raise RegistryProxyError(f"cannot bind {self.bind}:{self.port}: {exc}") from exc
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None
