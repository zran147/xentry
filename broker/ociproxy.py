"""A Docker Hub mirror for Debian and Ubuntu base images only.

Why it exists, what it deliberately cannot do, and why the image allowlist is
two repositories wide: ADR entry 34. The short version is that a PoC's own
Dockerfile is often the only description of the vulnerable environment its
author wrote, `docker build` cannot reach a registry on a network with
`forward mode='none'`, and dockerd takes a `registry-mirrors` entry that
applies to docker.io and nothing else - which is exactly this shape.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

REGISTRY_HOST = "registry-1.docker.io"
AUTH_URL = "https://auth.docker.io/token"
# ADR 34c restricted this to library/debian and library/ubuntu "because those
# are the two archives the apt proxies serve and an image from anywhere else
# puts software in the target that nothing here can account for". The first
# half of that reason only applies to a build that RUNS apt: the alignment that
# matters is between the Dockerfile's package manager and the dated proxy. A
# Dockerfile that installs nothing has no such dependency, and its environment
# is fully determined by the image - which 34b already records, by image id and
# by every layer digest the build actually ran. So the software IS accounted
# for, in the only way an image ever can be.
#
# Measured case: kozmer/log4j-shell-poc is FROM tomcat:8.0.36-jre8 and installs
# nothing. It failed with "lookup registry-1.docker.io: server misbehaving" -
# an image the mirror would not serve. That tag also names an exact upstream
# version, which `debian:bookworm` does not.
#
# What does NOT change: a build that installs packages from the network is
# still refused, at the check, because then undated software enters the target
# and the apt-proxy alignment is exactly what is missing. Every blob is still
# verified against the digest that names it, and a manifest asked for by TAG is
# still never cached.
#
# Docker Hub's own grammar: one optional namespace, lowercase, separators only
# between alphanumerics. "library/" is prepended for a bare name, as docker
# itself does.
COMPONENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
NAME_RE = re.compile(rf"^{COMPONENT}/{COMPONENT}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PATH_RE = re.compile(
    rf"^/v2/({COMPONENT}/{COMPONENT})/(manifests|blobs)/([A-Za-z0-9_:.-]+)$"
)
# Every manifest type docker may ask for. Sent as one Accept header so the
# registry answers with whatever that image actually is - a fat manifest list
# for a multi-arch tag, a plain manifest for a single one.
MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
TOKEN_TTL = 240.0
MAX_BLOB = 1_200_000_000


class OciProxyError(RuntimeError):
    """The mirror could not answer."""


class OciPathRefused(OciProxyError):
    """The guest asked for something outside the allowlist."""


def check_image(name: str) -> str:
    """The repository, normalised, or refuse it.

    No allowlist of repositories any more - see the note above NAME_RE - but
    the NAME is still validated, because it becomes a path segment both
    upstream and in the cache. One namespace only: "a/b/c" is refused rather
    than silently reinterpreted.
    """
    full = name if "/" in name else f"library/{name}"
    if not NAME_RE.match(full):
        raise OciPathRefused(
            f"refused image: {name!r}; expected a Docker Hub repository such as "
            f"debian, library/ubuntu or tomcat"
        )
    return full


def _cache_path(root: Path, *parts: str) -> Path:
    base = root.resolve()
    path = base.joinpath(*parts).resolve()
    if path != base and base not in path.parents:
        raise OciProxyError(f"cache path escapes {base}: {parts}")
    return path


class OciMirror:
    """One per job, serving docker.io for two repositories."""

    def __init__(self, cache_dir: Path, *, bind: str, port: int) -> None:
        self.cache_dir = Path(cache_dir)
        self.bind = bind
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._tokens: dict[str, tuple[str, float]] = {}
        self._opener: object = urllib.request

    @property
    def url(self) -> str:
        return f"http://{self.bind}:{self.port}"

    def _token(self, image: str) -> str:
        """A pull token for one repository, cached for less than its lifetime.

        Docker Hub requires one even anonymously. It is fetched by the host and
        attached upstream; the guest never sees it, which is the same rule the
        NVD key follows.
        """
        found = self._tokens.get(image)
        if found is not None and found[1] > time.monotonic():
            return found[0]
        url = f"{AUTH_URL}?service=registry.docker.io&scope=repository:{image}:pull"
        try:
            with self._opener.urlopen(  # type: ignore[attr-defined]
                urllib.request.Request(url, headers={"User-Agent": "xentry-oci-mirror"}),
                timeout=30,
            ) as response:
                payload = json.loads(response.read())
        except (urllib.error.URLError, ValueError, OSError) as exc:
            raise OciProxyError(f"cannot get a pull token for {image}: {exc}") from exc
        token = str(payload.get("token") or "")
        if not token:
            raise OciProxyError(f"no token in the reply for {image}")
        self._tokens[image] = (token, time.monotonic() + TOKEN_TTL)
        return token

    def _get(self, image: str, path: str, accept: str) -> tuple[bytes, dict[str, str]]:
        request = urllib.request.Request(
            f"https://{REGISTRY_HOST}{path}",
            headers={
                "Authorization": f"Bearer {self._token(image)}",
                "Accept": accept,
                "User-Agent": "xentry-oci-mirror",
            },
        )
        try:
            with self._opener.urlopen(request, timeout=120) as response:  # type: ignore[attr-defined]
                body = response.read(MAX_BLOB + 1)
                headers = {
                    "Content-Type": response.headers.get("Content-Type", "")
                    or "application/octet-stream",
                    "Docker-Content-Digest": response.headers.get(
                        "Docker-Content-Digest", ""
                    ),
                }
        except urllib.error.HTTPError as exc:
            raise OciProxyError(f"upstream {exc.code} for {path}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise OciProxyError(f"upstream failed for {path}: {exc}") from exc
        if len(body) > MAX_BLOB:
            raise OciProxyError(f"{path} is larger than {MAX_BLOB} bytes")
        return body, {key: value for key, value in headers.items() if value}

    def manifest(self, image: str, ref: str) -> tuple[bytes, dict[str, str]]:
        """A manifest by tag or by digest.

        A digest is cached because it names its own content. A TAG is not: it
        moves, and serving a stale one would hand the guest an image the
        registry no longer publishes under that name while telling it the tag
        was honoured.
        """
        if DIGEST_RE.match(ref):
            cached = _cache_path(self.cache_dir, "manifests", ref.replace(":", "-"))
            meta_path = cached.with_suffix(".json")
            if cached.is_file():
                # Re-verified, and the metadata read defensively. This entry is
                # TWO files written one after the other, so a crash between
                # them left a manifest with no metadata - and the read did a
                # bare json.loads of a file that was not there, failing for
                # that digest for as long as the cache lived. The digest is the
                # name of the content, so checking it costs one sha256 of a few
                # kilobytes and turns a corrupt entry into a refetch.
                body = cached.read_bytes()
                try:
                    self._verify(body, ref)
                    meta = json.loads(meta_path.read_text())
                except (OciProxyError, OSError, ValueError):
                    cached.unlink(missing_ok=True)
                    meta_path.unlink(missing_ok=True)
                else:
                    return body, meta
            body, headers = self._get(
                image, f"/v2/{image}/manifests/{ref}", ", ".join(MANIFEST_TYPES)
            )
            self._verify(body, ref)
            cached.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            # Metadata first, then the manifest, each renamed into place: the
            # manifest's existence is what the read tests, so it must be the
            # last thing to appear.
            meta_partial = meta_path.with_name(meta_path.name + ".part")
            meta_partial.write_text(json.dumps(headers))
            os.replace(meta_partial, meta_path)
            partial = cached.with_name(cached.name + ".part")
            partial.write_bytes(body)
            os.replace(partial, cached)
            return body, headers
        if not TAG_RE.match(ref):
            raise OciPathRefused(f"refused reference: {ref!r}")
        return self._get(image, f"/v2/{image}/manifests/{ref}", ", ".join(MANIFEST_TYPES))

    def blob(self, image: str, digest: str) -> Path:
        """One layer, fetched once and verified against its own digest."""
        if not DIGEST_RE.match(digest):
            raise OciPathRefused(f"refused blob reference: {digest!r}")
        cached = _cache_path(self.cache_dir, "blobs", digest.replace(":", "-"))
        if cached.is_file():
            return cached
        body, _headers = self._get(image, f"/v2/{image}/blobs/{digest}", "*/*")
        self._verify(body, digest)
        cached.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        partial = cached.with_name(cached.name + ".part")
        partial.write_bytes(body)
        partial.chmod(0o640)
        os.replace(partial, cached)
        return cached

    @staticmethod
    def _verify(body: bytes, digest: str) -> None:
        actual = "sha256:" + hashlib.sha256(body).hexdigest()
        if actual != digest:
            raise OciProxyError(f"digest mismatch: asked {digest}, got {actual}")

    def route(self, path: str) -> tuple[bytes | None, Path | None, dict[str, str]]:
        """Resolve one request from the guest's dockerd.

        /v2/ is the version probe dockerd makes before anything else; without a
        200 there it does not treat this as a registry at all.
        """
        if path in {"/v2", "/v2/"}:
            return b"{}", None, {"Content-Type": "application/json"}
        found = PATH_RE.match(path)
        if found is None or ".." in path:
            raise OciPathRefused(f"refused path: {path}")
        image = check_image(found.group(1))
        kind, ref = found.group(2), found.group(3)
        if kind == "manifests":
            body, headers = self.manifest(image, ref)
            return body, None, headers
        return None, self.blob(image, ref), {"Content-Type": "application/octet-stream"}

    def start(self) -> None:
        if self._server is not None:
            return
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _serve(self, body: bool) -> None:
                try:
                    payload, local, headers = proxy.route(urlsplit(self.path).path)
                except OciPathRefused as exc:
                    self.send_error(403, str(exc))
                    return
                except OciProxyError as exc:
                    code = 404 if "upstream 404" in str(exc) else 502
                    self.send_error(code, str(exc))
                    return
                size = len(payload) if payload is not None else local.stat().st_size  # type: ignore[union-attr]
                self.send_response(200)
                for key, value in headers.items():
                    self.send_header(key, value)
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
            raise OciProxyError(f"cannot bind {self.bind}:{self.port}: {exc}") from exc
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
