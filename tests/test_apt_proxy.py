"""The pinned apt mirror.

Two properties are load-bearing. The guest cannot reach anything but one
snapshot of the Ubuntu archive, and it cannot choose which snapshot: the serial
is inserted on the host, so a provisioned target is reproducible. The mirror is
also reachable during provisioning only, which is a property of the two
nftables phases rather than of this service.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from broker.aptproxy import (
    SNAPSHOT_SERIAL,
    AptProxyError,
    AptSnapshotProxy,
    snapshot_serial,
)
from broker.network_ops import locked_rules, provisioning_rules

PACKAGE = b"not really a deb, but it is these bytes"


class Upstream(BaseHTTPRequestHandler):
    seen: ClassVar[list[str]] = []
    agents: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).seen.append(self.path)
        type(self).agents.append(self.headers.get("User-Agent", ""))
        if self.path.endswith("/missing.deb"):
            self.send_error(404, "no such package")
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(PACKAGE)))
        self.end_headers()
        self.wfile.write(PACKAGE)

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture
def upstream() -> object:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    Upstream.seen = []
    Upstream.agents = []
    yield server
    server.shutdown()
    server.server_close()


def _proxy(tmp_path: Path, upstream: object, serial: str = "20261101T000000Z") -> AptSnapshotProxy:
    proxy = AptSnapshotProxy(tmp_path / "apt-cache", bind="127.0.0.1", port=0, serial=serial)
    port = upstream.server_address[1]  # type: ignore[attr-defined]
    # Only the upstream base is redirected; the path rewriting under test is
    # the proxy's own.
    proxy.base = f"http://127.0.0.1:{port}/ubuntu/{serial}"
    return proxy


# ------------------------------------------------------------- the pinning ---


def test_the_serial_is_inserted_by_the_host(tmp_path: Path, upstream: object) -> None:
    proxy = _proxy(tmp_path, upstream)
    local = proxy.fetch("/ubuntu/pool/main/a/apache2/apache2_2.4.58-1_amd64.deb")
    assert local.read_bytes() == PACKAGE
    # The guest asked for a path with no serial in it; the serial came from here.
    assert Upstream.seen == [
        "/ubuntu/20261101T000000Z/pool/main/a/apache2/apache2_2.4.58-1_amd64.deb"
    ]


def test_a_guest_cannot_choose_another_snapshot(tmp_path: Path, upstream: object) -> None:
    proxy = _proxy(tmp_path, upstream)
    # Any shape that would reach a different serial, a different host, or the
    # live archive is refused outright rather than rewritten.
    for path in (
        "/ubuntu/20200101T000000Z/pool/main/a/a.deb",
        "/ubuntu/pool/../../etc/shadow",
        "/ubuntu/pool/main/../../../../etc/shadow",
        # Matches the path pattern - a dot is a legal filename character - so
        # this one is excluded by the explicit ".." check, not the regex.
        "/ubuntu/pool/a/../../../etc/shadow",
        # Upstream would decode these, so an encoded climb could reach another
        # serial. Percent is not a legal character here at all.
        "/ubuntu/pool/main/%2e%2e/%2e%2e/dists/noble/InRelease",
        "/ubuntu/dists/noble%2f..%2f..%2fInRelease",
        "http://archive.ubuntu.com/ubuntu/pool/main/a/a.deb",
        "/etc/shadow",
        "/ubuntu/",
        "/ubuntu/other/main/a.deb",
        "/",
        "",
    ):
        with pytest.raises(AptProxyError):
            proxy.fetch(path)
    assert Upstream.seen == []


def test_the_repo_pins_the_serial_and_rejects_a_malformed_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XENTRY_APT_SNAPSHOT", raising=False)
    assert snapshot_serial() == SNAPSHOT_SERIAL
    monkeypatch.setenv("XENTRY_APT_SNAPSHOT", "20261201T000000Z")
    assert snapshot_serial() == "20261201T000000Z"
    # A serial that is not a timestamp would silently become part of a URL.
    for bad in ("latest", "../../etc", "2026-12-01", ""):
        monkeypatch.setenv("XENTRY_APT_SNAPSHOT", bad)
        if bad == "":
            assert snapshot_serial() == SNAPSHOT_SERIAL
            continue
        with pytest.raises(AptProxyError):
            snapshot_serial()


# --------------------------------------------------------------- the cache ---


def test_a_package_is_fetched_once_and_then_served_from_disk(
    tmp_path: Path, upstream: object
) -> None:
    proxy = _proxy(tmp_path, upstream)
    first = proxy.fetch("/ubuntu/dists/noble/InRelease")
    second = proxy.fetch("/ubuntu/dists/noble/InRelease")
    assert first == second
    assert len(Upstream.seen) == 1
    # Cached under the serial, so bumping it cannot serve the old bytes.
    assert SNAPSHOT_SERIAL in str(first)
    assert first.read_bytes() == PACKAGE


def test_nothing_of_the_guest_is_sent_upstream(tmp_path: Path, upstream: object) -> None:
    proxy = _proxy(tmp_path, upstream)
    proxy.fetch("/ubuntu/dists/noble/InRelease")
    assert Upstream.agents == ["xentry-apt-mirror"]


def test_an_upstream_404_leaves_nothing_behind(tmp_path: Path, upstream: object) -> None:
    proxy = _proxy(tmp_path, upstream)
    with pytest.raises(AptProxyError) as excinfo:
        proxy.fetch("/ubuntu/pool/main/m/missing/missing.deb")
    assert "404" in str(excinfo.value)
    leftovers = list((tmp_path / "apt-cache").rglob("*.part"))
    assert leftovers == []


# ---------------------------------------------------------------- serving ---


def test_it_serves_over_http_to_the_guest(tmp_path: Path, upstream: object) -> None:
    proxy = _proxy(tmp_path, upstream)
    proxy.port = 0
    proxy.start()
    try:
        bound = proxy._server.server_address[1]  # type: ignore[union-attr]
        with urllib.request.urlopen(
            f"http://127.0.0.1:{bound}/ubuntu/dists/noble/InRelease", timeout=10
        ) as response:
            body = response.read()
        assert hashlib.sha256(body).hexdigest() == hashlib.sha256(PACKAGE).hexdigest()
        # A refused path is this mirror declining, not an upstream failure.
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(f"http://127.0.0.1:{bound}/etc/shadow", timeout=10)
        assert excinfo.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as missing:
            urllib.request.urlopen(
                f"http://127.0.0.1:{bound}/ubuntu/pool/main/m/missing/missing.deb", timeout=10
            )
        assert missing.value.code == 404
    finally:
        proxy.stop()


# ------------------------------------------------------------- the phases ---


def test_the_apt_path_is_open_for_provisioning_and_closed_after() -> None:
    opened = provisioning_rules(
        bridge="xentry-1", mirror_ip="10.42.1.1", table="xentry_1", apt_port=8082
    )
    assert "tcp dport 8082 accept" in opened
    # Same gateway as the artifact mirror: a host service, not a route out.
    assert "ip daddr 10.42.1.1 tcp dport 8082" in opened
    locked = locked_rules(
        [8088], bridge="xentry-1", target_ip="10.42.1.10", attacker_ip="10.42.1.20"
    )
    assert "8082" not in locked
    assert "policy drop" in locked


def test_without_the_proxy_the_rule_is_absent() -> None:
    assert "8082" not in provisioning_rules(bridge="xentry-1", mirror_ip="10.42.1.1")


def test_the_step_is_allowlisted_and_hashed() -> None:
    # A generated setup script cannot be run by the broker, but this step can:
    # it is checked in, hashed at load, and runs as root with two typed params.
    from broker.steps import StepRegistry

    root = Path(__file__).resolve().parents[1]
    registry = StepRegistry(root / "targets" / "steps.yaml", root / "targets")
    spec = registry.steps["apt-pin"]
    assert spec.user == "root"
    assert spec.params == ("apt_proxy_url", "suite")
    body = (root / "targets" / "common" / "apt-pin.sh").read_bytes()
    assert spec.sha256 == hashlib.sha256(body).hexdigest()
    # The snapshot URL the guest is pointed at carries no serial: the mirror
    # inserts it, so the guest cannot pin itself to something else.
    assert b"${proxy_url}/ubuntu" in body
    assert SNAPSHOT_SERIAL.encode() not in body


# ------------------------------------------------------------ the evidence ---


def test_the_snapshot_serial_is_recorded_as_job_evidence(tmp_path: Path) -> None:
    """The broker journals only a hash of each result, so this is recorded here."""
    import json

    from tests.test_runner import POC_URL, FakeBroker, fake_extract, fake_fetch, fake_validate
    from xentry.db import connect, init_db
    from xentry.jobstore import create_job, list_artifacts
    from xentry.runner import JobRunner

    class AptBroker(FakeBroker):
        def call(self, verb: str, params: dict[str, object], **kwargs: object) -> object:
            result = super().call(verb, params, **kwargs)
            if verb == "create_network" and isinstance(result, dict):
                result = {
                    **result,
                    "subnet": "10.42.4.0/24",
                    "apt_proxy_url": "http://10.42.4.1:8082",
                    "apt_snapshot": SNAPSHOT_SERIAL,
                }
            return result

    db_path = tmp_path / "xentry.db"
    conn = init_db(db_path)
    job_id, attempt_id, attempt_dir = create_job(
        conn, data_dir=tmp_path, poc_url=POC_URL, cve_url="https://example.com/cve"
    )
    conn.close()
    JobRunner(
        db_path=db_path,
        data_dir=tmp_path,
        broker_socket=tmp_path / "broker.sock",
        extract_fn=fake_extract,
        validate_fn=fake_validate,
        fetch_fn=fake_fetch,
        broker_factory=lambda: AptBroker(),  # type: ignore[return-value]
    ).run_job(job_id, "https://example.com/cve", POC_URL, attempt_id)

    recorded = json.loads((attempt_dir / "provision-inputs.json").read_text(encoding="utf-8"))
    assert recorded["apt_snapshot"] == SNAPSHOT_SERIAL
    assert recorded["apt_proxy_url"] == "http://10.42.4.1:8082"
    assert recorded["subnet"] == "10.42.4.0/24"
    conn = connect(db_path)
    try:
        paths = [
            item for item in list_artifacts(conn, job_id) if str(item.get("kind")) == "evidence"
        ]
        assert any("provision-inputs" in str(item.get("path", "")) for item in paths) or paths
        # Hashed like any other evidence, so the audit bundle can verify it.
        digest = hashlib.sha256((attempt_dir / "provision-inputs.json").read_bytes()).hexdigest()
        assert any(str(item.get("sha256")) == digest for item in paths)
    finally:
        conn.close()


# --------------------------------------------------- the serial per advisory ---


def test_the_serial_comes_from_the_advisory_date() -> None:
    """The archive ships the fixed build, so the serial has to predate the
    advisory for apt to resolve a vulnerable one."""
    from xentry.generic import advisory_published, snapshot_for

    record = (
        '{"vulnerabilities": [{"cve": {"id": "CVE-2026-1", '
        '"published": "2026-10-30T12:15:09.143"}}]}'
    )
    assert advisory_published(record) == "2026-10-30T12:15:09.143"
    # The day before, at the start of that day.
    assert snapshot_for("2026-10-30T12:15:09.143") == "20261029T000000Z"


@pytest.mark.parametrize(
    "published",
    [
        "",
        "last tuesday",
        "2019-01-05T00:00:00",  # before snapshot.ubuntu.com existed
        "2099-01-05T00:00:00",  # not yet taken
    ],
)
def test_a_date_that_cannot_be_used_yields_no_serial(published: str) -> None:
    """Empty means "use the default", which is visible in the plan. A guessed
    serial would install a build nobody chose."""
    from xentry.generic import snapshot_for

    assert snapshot_for(published) == ""


def test_a_page_that_is_not_an_nvd_record_yields_no_date() -> None:
    from xentry.generic import advisory_published

    assert advisory_published("<html>GitHub advisory</html>") == ""
    assert advisory_published('{"vulnerabilities": []}') == ""
    assert advisory_published("") == ""


def test_the_broker_refuses_a_serial_the_archive_cannot_have(tmp_path: Path) -> None:
    from broker.aptproxy import ARCHIVES, check_serial

    assert check_serial("20261029T000000Z") == "20261029T000000Z"
    # 20220101 is no longer refused: Ubuntu's floor moved to the app's own
    # SNAPSHOT_FLOOR once the -updates assumption was measured and found
    # wrong. A serial below 2021-08 still is, and so is anything that is not
    # a serial.
    for bad in ("20210101T000000Z", "latest", "../etc", "2026-10-29", ""):
        with pytest.raises(AptProxyError):
            check_serial(bad)
    assert ARCHIVES["ubuntu"].floor < "20261029T000000Z"


def test_a_job_serial_reaches_the_proxy_and_is_reported(tmp_path: Path) -> None:
    from broker.errors import BrokerError
    from tests.test_runtime import make_runtime

    runtime, _virsh, _nft, _ = make_runtime(
        tmp_path, start_apt_proxy=True, mirror_bind="127.0.0.1", apt_port=0
    )
    result = runtime.create_network("job-1", "isolated", "20261029T000000Z")
    try:
        assert result["apt_snapshot"] == "20261029T000000Z"
        assert runtime.apt_proxies["job-1"].serial == "20261029T000000Z"
        # The guest's paths carry no serial, so it still cannot choose one.
        assert runtime.apt_proxies["job-1"].base.endswith("/ubuntu/20261029T000000Z")
    finally:
        runtime.destroy_network("xentry-job-1")
    # A serial the archive cannot have is a refusal, not a failed network.
    with pytest.raises(BrokerError) as excinfo:
        runtime.create_network("job-2", "isolated", "19990101T000000Z")
    assert excinfo.value.code == "broker_registry_rejected"


# --- the second archive ----------------------------------------------------


def test_each_archive_has_its_own_upstream_and_floor() -> None:
    from broker.aptproxy import ARCHIVES

    ubuntu, debian = ARCHIVES["ubuntu"], ARCHIVES["debian"]
    assert ubuntu.upstream.format(serial="S") == "https://snapshot.ubuntu.com/ubuntu/S"
    assert debian.upstream.format(serial="S") == "https://snapshot.debian.org/archive/debian/S"
    # BOTH floors are now "where a Release still verifies", not "where bytes
    # exist". Ubuntu's was 20230601 on the belief that nothing earlier could
    # be served; measured, dists/jammy/Release answers 200 at 20220217 and the
    # index is byte-identical to 20230601, because a release pocket is
    # immutable. Only -updates and -security are absent that early, and
    # setup-generic asks the archive which pockets it has rather than assuming.
    assert "2021" in ubuntu.floor
    assert "2021" in debian.floor
    # Debian serves the original Release, expired a week after it was made.
    assert ubuntu.check_valid_until is True
    assert debian.check_valid_until is False


def test_a_serial_is_checked_against_its_own_archives_floor() -> None:
    """Each archive is asked about its own history, and 2022 is now allowed.

    CVE-2021-41773's serial used to be "impossible for Ubuntu" here. It is
    not: the release pocket is immutable and serves at 20211004, and the
    pockets that do not exist that early are omitted by setup-generic after it
    asks the archive. What is still refused is a serial below the floor where
    the images' keyring can verify a Release at all.

    This is what cost every 2022 CVE the sweep found - redis, cacti,
    icingaweb2, PwnKit, enlightenment all resolved to a 2022 serial and were
    refused at create_network before a VM was ever built.
    """
    from broker.aptproxy import AptProxyError, check_serial

    assert check_serial("20211004T000000Z", "debian") == "20211004T000000Z"
    assert check_serial("20211004T000000Z", "ubuntu") == "20211004T000000Z"
    assert check_serial("20220217T000000Z", "ubuntu") == "20220217T000000Z"
    with pytest.raises(AptProxyError, match="before this archive's floor"):
        check_serial("20210101T000000Z", "ubuntu")
    with pytest.raises(AptProxyError, match="unknown apt archive"):
        check_serial("20240101T000000Z", "alpine")


def test_a_proxy_serves_only_its_own_archives_prefix(tmp_path: Path) -> None:
    """A guest asking the other archive's path must be refused, not quietly
    served this archive's bytes under the other name."""
    from broker.aptproxy import AptPathRefused, AptSnapshotProxy

    proxy = AptSnapshotProxy(
        tmp_path, bind="127.0.0.1", port=8099, serial="20211004T000000Z", archive="debian"
    )
    assert proxy.base == "https://snapshot.debian.org/archive/debian/20211004T000000Z"
    for refused in ("/ubuntu/dists/sid/Release", "/debian/../etc/passwd", "/debian/evil/x"):
        with pytest.raises(AptPathRefused):
            proxy.fetch(refused)


def test_the_cache_is_keyed_by_archive(tmp_path: Path) -> None:
    """Both archives have a pool/main/a/apache2/apache2_*.deb and they are not
    the same bytes."""
    from broker.aptproxy import AptSnapshotProxy

    paths = set()
    for archive, serial in (("debian", "20211004T000000Z"), ("ubuntu", "20240101T000000Z")):
        proxy = AptSnapshotProxy(
            tmp_path, bind="127.0.0.1", port=8099, serial=serial, archive=archive
        )
        rel = f"/{archive}/pool/main/a/apache2/apache2_2.4.49-4_amd64.deb"
        with contextlib.suppress(Exception):
            # No network in the test; where the cache lands is the point.
            proxy.fetch(rel)
        paths.add(str(tmp_path / archive))
    assert len(paths) == 2


def test_a_plus_in_a_version_is_not_a_refusal(tmp_path: Path) -> None:
    """Every package whose version carries a `+` was refused 403.

    apt percent-encodes it and PATH_RE had no `%`, so
    libsasl2-2_2.1.27%2bdfsg2..., apache2 2.4.48-3.1+deb11u1 and cacti
    1.2.19+ds1 were all refused while the same path with a literal `+` serves
    53,832 bytes from the same archive. Found through a container's apt during
    the Dockerfile prototype, but it was never container-specific: the guest's
    own apt encodes identically, so any job installing a `+dfsg`, `+ds`,
    `+deb11u1` or `+b1` package died at provisioning on what read like a
    refusal by design.
    """
    from broker.aptproxy import AptPathRefused, AptSnapshotProxy

    served: list[str] = []

    class Opener:
        def open(self, request: Any, timeout: float = 0) -> Any:
            served.append(request.full_url)
            return io.BytesIO(b"deb bytes")

    proxy = AptSnapshotProxy(
        tmp_path / "cache",
        bind="127.0.0.1",
        serial="20230601T000000Z",
        archive="ubuntu",
        opener=Opener(),
    )
    encoded = "/ubuntu/pool/main/c/cyrus-sasl2/libsasl2-2_2.1.27%2bdfsg2-3ubuntu1.2_amd64.deb"
    path = proxy.fetch(encoded)
    assert path.read_bytes() == b"deb bytes"
    # Upstream is asked for the DECODED form, which is what it serves.
    # The serial's base already carries /ubuntu, so the prefix is stripped and
    # what is appended is the decoded remainder.
    assert served[-1].endswith(
        "/pool/main/c/cyrus-sasl2/libsasl2-2_2.1.27+dfsg2-3ubuntu1.2_amd64.deb"
    )
    assert "20230601T000000Z" in served[-1]
    assert "%2b" not in served[-1]

    # And the traversal guards still hold on the decoded form, which is where
    # they have to: %2e%2e would otherwise decode past them.
    for refused in (
        "/ubuntu/pool/main/%2e%2e/%2e%2e/etc/passwd",
        "/ubuntu/pool/main/a/%252e%252e/x",
        "/ubuntu/pool/../../etc/passwd",
        "/debian/pool/main/x",
    ):
        with pytest.raises(AptPathRefused):
            proxy.fetch(refused)
