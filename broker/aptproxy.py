"""Pinned apt mirror for target provisioning.

A setup script for a CVE nobody wired by hand cannot install what it needs:
the isolated network has no route off its own bridge, and the artifact mirror
serves a closed allowlist of pinned files, not a package archive. This serves
Ubuntu packages to the guest without giving it a way out.

It is a reverse proxy, not a forward proxy. The guest's sources.list points at
this service and it rewrites each path onto one timestamped snapshot of the
Ubuntu archive; it never reads a destination out of the request, so there is no
host field to validate, no CONNECT, and nothing the guest can aim elsewhere.

The serial is the point. ``apt-get install apache2`` against the live archive
resolves to whatever is current that day, which would make a provisioned target
unreproducible - the one property the whole lab rests on. Against a fixed
snapshot the same resolution repeats forever, and the serial is reported with
the network so it is recorded as job evidence.
"""

from __future__ import annotations

import os
import re
import shutil
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

# Ubuntu's timestamped archive. Bumping this serial is a deliberate act that
# changes what every later provision installs, so it lives in the repo rather
# than in the environment; XENTRY_APT_SNAPSHOT overrides it for a one-off.
SNAPSHOT_HOST = "snapshot.ubuntu.com"
SNAPSHOT_SERIAL = "20261101T000000Z"
SERIAL_RE = re.compile(r"^\d{8}T\d{6}Z$")


@dataclass(frozen=True)
class Archive:
    """One upstream snapshot service, and the floor its history starts at."""

    name: str
    host: str
    # The path the guest's sources.list points at, and the prefix every request
    # must carry. Ubuntu serves /ubuntu/<serial>/..., Debian
    # /archive/debian/<serial>/....
    prefix: str
    upstream: str
    floor: str
    # A snapshot Release expired the week it was made, so apt refuses it on
    # freshness alone while its signature is still perfectly good. Ubuntu's
    # snapshot service rewrites Valid-Until; Debian's serves the original.
    check_valid_until: bool
    # (prefix, upstream) pairs this archive also answers for. A container's
    # sources.list asks one host:port for both /debian and /debian-security,
    # and `docker build` takes no volume flag, so the file cannot be rewritten
    # to split them. The gate does not loosen: a request still has to match one
    # of THIS archive's prefixes, and the cache stays keyed per matched name so
    # two archives' pool/main/a/apache2 cannot collide.
    companions: tuple[tuple[str, str], ...] = ()

    def routes(self, serial: str) -> tuple[tuple[str, str, str], ...]:
        """(name, prefix, upstream base) for this archive and its companions."""
        return ((self.name, self.prefix, self.upstream.format(serial=serial)),) + tuple(
            (prefix, prefix, upstream.format(serial=serial))
            for prefix, upstream in self.companions
        )


ARCHIVES = {
    item.name: item
    for item in (
        Archive(
            name="ubuntu",
            host=SNAPSHOT_HOST,
            prefix="ubuntu",
            upstream="https://snapshot.ubuntu.com/ubuntu/{serial}",
            # snapshot.ubuntu.com captured -updates and -security from about
            # 2023-06, and this floor was set to that date on the assumption
            # that an earlier serial "has nothing to serve". Measured, that is
            # wrong: dists/jammy/Release answers 200 at 20220217 and the index
            # is byte-identical to 20230601, because a release pocket is
            # immutable once published. Only the two moving pockets are
            # missing, and setup-generic now asks the archive which it has
            # rather than assuming.
            #
            # So the floor is the app's own SNAPSHOT_FLOOR: the point from
            # which the keyring in these images can still verify a Release
            # file. Serials between the two dates install from the release
            # pocket alone - which for reproducing a flaw is the better
            # pocket anyway, since -updates is where the fix would be.
            floor="20210801T000000Z",
            check_valid_until=True,
        ),
        Archive(
            name="debian",
            host="snapshot.debian.org",
            prefix="debian",
            upstream="https://snapshot.debian.org/archive/debian/{serial}",
            companions=(
                (
                    "debian-security",
                    "https://snapshot.debian.org/archive/debian-security/{serial}",
                ),
            ),
            # Debian's archive reaches back to 2005, but apt has to verify the
            # Release and a current keyring only covers signatures from the
            # bullseye key onward. Measured against today's keyring: a 2022 and
            # a 2024 serial verify, 2020 and earlier do not. The floor is where
            # verification still holds rather than where the archive starts;
            # going further back needs the era's keyring served as a pinned
            # artifact, which is not built.
            floor="20210801T000000Z",
            check_valid_until=False,
        ),
    )
}
# Everything apt fetches lives under /ubuntu: dists/ for indexes, pool/ for
# packages. Anything else is not a package request and is refused.
#
# Percent-encoding is deliberately not allowed. Upstream would decode it, so
# an encoded traversal could climb out of this serial's prefix and serve a
# different snapshot - losing the one property this service exists for. The
# archive does not need it: epochs are not part of a pool filename, and no
# Filename in noble/main carries a percent. A package that somehow needed one
# fails here, loudly, rather than quietly unpinning the provision.
PATH_RE = re.compile(
    r"^/(ubuntu|debian|debian-security)/(dists|pool)/[A-Za-z0-9][A-Za-z0-9._+~/-]*$"
)
UPSTREAM_TIMEOUT_S = 60


class AptProxyError(RuntimeError):
    """The apt mirror could not start or serve."""


class AptPathRefused(AptProxyError):
    """The request was not a package request this mirror will make."""


def check_archive(name: str) -> Archive:
    archive = ARCHIVES.get(name or "ubuntu")
    if archive is None:
        raise AptProxyError(f"unknown apt archive: {name!r}")
    return archive


def check_serial(serial: str, archive: str = "ubuntu") -> str:
    """Accept a serial only if it is one this archive could serve."""
    if not SERIAL_RE.match(serial):
        raise AptProxyError(f"invalid apt snapshot serial: {serial!r}")
    floor = check_archive(archive).floor
    if serial < floor:
        raise AptProxyError(
            f"{archive} snapshot serial {serial} is before this archive's floor {floor}"
        )
    return serial


def snapshot_serial() -> str:
    serial = os.environ.get("XENTRY_APT_SNAPSHOT", "").strip() or SNAPSHOT_SERIAL
    return check_serial(serial)


def _cache_path(root: Path, serial: str, rel: str) -> Path:
    # The regex already excludes "..", but the resolved path is checked against
    # the cache root as well: a path check is cheap and a cache escape would be
    # a write anywhere the broker can write.
    base = (root / serial).resolve()
    path = (base / rel.lstrip("/")).resolve()
    if path != base and base not in path.parents:
        raise AptProxyError(f"cache path escapes {base}: {rel}")
    return path


class AptSnapshotProxy:
    def __init__(
        self,
        cache_dir: Path,
        *,
        bind: str,
        port: int = 8082,
        serial: str | None = None,
        archive: str = "ubuntu",
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.bind = bind
        self.port = port
        self.archive = check_archive(archive)
        self.serial = (
            check_serial(serial, self.archive.name) if serial else snapshot_serial()
        )
        self.base = self.archive.upstream.format(serial=self.serial)
        self.opener = opener or urllib.request.build_opener()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.bind}:{self.port}"

    def fetch(self, path: str) -> Path:
        """Return a local file for a guest request path, fetching it once."""
        # Decoded first, because apt percent-encodes `+` and PATH_RE has no
        # `%`: every package whose version carries one - libsasl2-2
        # 2.1.27+dfsg2, apache2 2.4.48-3.1+deb11u1, cacti 1.2.19+ds1 - was
        # refused 403 while the same path with a literal `+` serves 53,832
        # bytes. Found through a container's apt, but it was never
        # container-specific: the guest's own apt encodes identically, so any
        # job installing a `+dfsg`, `+ds`, `+deb11u1` or `+b1` package died at
        # provisioning on what read like a refusal by design.
        #
        # ".." is excluded explicitly as well as by the cache-path check: the
        # character class admits a dot, so "pool/a/../.." matches the pattern.
        # Checked on the DECODED form, so %2e%2e cannot smuggle one past, and
        # a leftover `%` after one decode is refused rather than decoded again.
        decoded = urllib.parse.unquote(path)
        if ".." in decoded or "%" in decoded or not PATH_RE.match(decoded):
            raise AptPathRefused(f"refused path: {path}")
        # The prefix is this archive's, not whichever the request carried: a
        # guest asking /debian/... of an Ubuntu-backed proxy must be refused
        # rather than silently served the Ubuntu path under another name.
        for name, prefix, upstream in self.archive.routes(self.serial):
            if decoded.startswith(f"/{prefix}/"):
                rel = decoded[len(prefix) + 1 :]
                # self.base, not the recomputed upstream, for the PRIMARY
                # archive: it is the seam the tests redirect to a local server,
                # and recomputing it here silently ignored their override.
                base = self.base if name == self.archive.name else upstream
                break
        else:
            raise AptPathRefused(f"refused path for {self.archive.name}: {path}")
        # Keyed by archive as well as serial: both archives have a
        # pool/main/a/apache2/apache2_*.deb and they are not the same bytes.
        cached = _cache_path(self.cache_dir / name, self.serial, rel)
        if cached.is_file():
            return cached
        cached.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        partial = cached.with_name(cached.name + ".part")
        # No request header is carried over from the guest and none is added
        # beyond a generic agent: the guest must not be able to shape what the
        # host sends to a third party.
        request = urllib.request.Request(
            base + rel, headers={"User-Agent": "xentry-apt-mirror"}
        )
        try:
            with (
                self.opener.open(request, timeout=UPSTREAM_TIMEOUT_S) as response,
                partial.open("wb") as handle,
            ):
                shutil.copyfileobj(response, handle)
        except urllib.error.HTTPError as exc:
            partial.unlink(missing_ok=True)
            raise AptProxyError(f"upstream {exc.code} for {rel}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            partial.unlink(missing_ok=True)
            raise AptProxyError(f"upstream unreachable for {rel}: {exc}") from exc
        partial.chmod(0o640)
        os.replace(partial, cached)
        return cached

    def start(self) -> None:
        if self._server is not None:
            return
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _serve(self, body: bool) -> None:
                path = urlsplit(self.path).path
                try:
                    local = proxy.fetch(path)
                except AptPathRefused as exc:
                    # Not an upstream failure: this mirror will not ask for it.
                    self.send_error(403, str(exc))
                    return
                except AptProxyError as exc:
                    self.send_error(404 if "upstream 404" in str(exc) else 502, str(exc))
                    return
                size = local.stat().st_size
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.end_headers()
                if body:
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
            raise AptProxyError(f"cannot bind {self.bind}:{self.port}: {exc}") from exc
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._thread = None
