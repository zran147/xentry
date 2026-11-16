"""Docker Hub for Debian and Ubuntu base images, and nothing else.

A PoC's Dockerfile is often the only description of the vulnerable environment
its author wrote, and `docker build` cannot reach a registry on a network with
forward=none. What this path costs is provenance - a base tag is not a version
and Docker Hub keeps no history of what one pointed at - so the whole point of
the tests here is that what it does guarantee, it guarantees: the allowlist,
the digest of every layer, and that a moving tag is never served from cache.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from broker.ociproxy import OciMirror, OciPathRefused, OciProxyError, check_image


class FakeHub:
    """Stands in for registry-1.docker.io, and records every request."""

    def __init__(self, bodies: dict[str, bytes]) -> None:
        self.bodies = bodies
        self.asked: list[str] = []

    def urlopen(self, request: Any, timeout: float = 0) -> Any:
        url = request.full_url
        self.asked.append(url)
        if "auth.docker.io" in url:
            body = json.dumps({"token": "t"}).encode()
        else:
            body = self.bodies.get(url, b"")
            if not body:
                import urllib.error

                raise urllib.error.HTTPError(url, 404, "no", {}, None)  # type: ignore[arg-type]

        class Response:
            headers = type(
                "H", (), {"get": staticmethod(lambda key, default="":
                                              {"Content-Type": "application/json",
                                               "Docker-Content-Digest": "sha256:x"}
                                              .get(key, default))}
            )()

            def read(self, _size: int | None = None) -> bytes:
                return body

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_a: object) -> None:
                return None

        return Response()


def _mirror(tmp_path: Path, bodies: dict[str, bytes]) -> tuple[OciMirror, FakeHub]:
    hub = FakeHub(bodies)
    mirror = OciMirror(tmp_path / "cache", bind="10.42.1.1", port=8086)
    mirror._opener = hub  # the seam the tests drive
    return mirror, hub


@pytest.mark.parametrize(
    ("name", "expected"),
    [("debian", "library/debian"), ("ubuntu", "library/ubuntu"),
     ("library/debian", "library/debian"),
     # No longer two repositories wide. ADR 34c restricted it "because those
     # are the two archives the apt proxies serve", and that reason applies
     # only to a build that RUNS apt: the alignment that matters is between the
     # Dockerfile's package manager and the dated proxy. A build that installs
     # nothing has no such dependency, and 34b already records the image id and
     # every layer digest it ran - so the software is accounted for in the only
     # way an image ever can be. kozmer/log4j-shell-poc is FROM
     # tomcat:8.0.36-jre8, installs nothing, and failed on an image the mirror
     # would not serve; that tag also names an exact upstream version, which
     # debian:bookworm does not.
     ("tomcat", "library/tomcat"), ("php", "library/php"),
     ("bitnami/grafana", "bitnami/grafana"), ("alpine", "library/alpine")],
)
def test_a_docker_hub_repository_is_served(name: str, expected: str) -> None:
    assert check_image(name) == expected


@pytest.mark.parametrize(
    "name",
    ["../etc", "a/b/c", "UPPER", "library/UPPER", "-lead", "lib/", "/x", "a//b", ""],
)
def test_a_name_outside_docker_hubs_grammar_is_refused(name: str) -> None:
    """The repository is still validated, because it becomes a path segment.

    What moved is the POLICY, not the parsing: which images a job may use is
    decided at the check, where the Dockerfile is read, and a build that
    installs packages from the network is refused there. The mirror's job is
    to serve a well-formed name safely - one namespace only, so "a/b/c" is
    refused rather than silently reinterpreted.
    """
    with pytest.raises(OciPathRefused):
        check_image(name)


@pytest.mark.parametrize(
    "path",
    [
        # library/alpine and evil/debian are WELL-FORMED names now, so they
        # are no longer refused here - a nonexistent repository fails upstream
        # with a 404 instead, which is the registry's answer to give.
        "/v2/library/debian/manifests/../../etc/passwd",
        "/v2/library/debian/blobs/sha256:nothex",
        "/v2/library/debian/blobs/../../../etc/passwd",
        "/v2/a/b/c/manifests/latest",
        "/v2/library/UPPER/manifests/latest",
        "/etc/passwd",
        "/v2/library/debian/tags/list",
        "/v2/library/debian/manifests/",
    ],
)
def test_a_path_outside_the_shape_is_refused(tmp_path: Path, path: str) -> None:
    mirror, hub = _mirror(tmp_path, {})
    with pytest.raises(OciPathRefused):
        mirror.route(path)
    assert hub.asked == [], "it asked upstream before refusing"


def test_dockerd_gets_its_version_probe(tmp_path: Path) -> None:
    """Without a 200 on /v2/ dockerd does not treat this as a registry at all."""
    mirror, _hub = _mirror(tmp_path, {})
    for path in ("/v2/", "/v2"):
        body, local, headers = mirror.route(path)
        assert body == b"{}" and local is None
        assert headers["Content-Type"] == "application/json"


def test_a_layer_is_verified_against_the_digest_that_names_it(tmp_path: Path) -> None:
    """The one guarantee this path does make. A registry that handed back the
    wrong bytes would otherwise put them in the target unremarked."""
    body = b"a layer"
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    url = f"https://registry-1.docker.io/v2/library/debian/blobs/{digest}"
    mirror, hub = _mirror(tmp_path, {url: body})
    assert mirror.blob("library/debian", digest).read_bytes() == body
    # Cached by digest, so the second ask costs nothing.
    before = len(hub.asked)
    mirror.blob("library/debian", digest)
    assert len(hub.asked) == before

    wrong = "sha256:" + "d" * 64
    other = f"https://registry-1.docker.io/v2/library/debian/blobs/{wrong}"
    mirror2, _hub2 = _mirror(tmp_path / "two", {other: b"not that layer"})
    with pytest.raises(OciProxyError, match="digest mismatch"):
        mirror2.blob("library/debian", wrong)
    assert list((tmp_path / "two" / "cache").rglob("*.part")) == []
    assert list((tmp_path / "two" / "cache").rglob("blobs/*")) == []


def test_a_tag_is_never_served_from_cache_but_a_digest_is(tmp_path: Path) -> None:
    """A tag moves. Serving a stale one would hand the guest an image the
    registry no longer publishes under that name, while telling it the tag was
    honoured - which is the whole reason this mirror cannot date anything.
    """
    manifest = json.dumps({"schemaVersion": 2, "layers": []}).encode()
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    base = "https://registry-1.docker.io/v2/library/debian/manifests"
    mirror, hub = _mirror(tmp_path, {f"{base}/bullseye": manifest,
                                     f"{base}/{digest}": manifest})

    mirror.manifest("library/debian", "bullseye")
    first = len([u for u in hub.asked if "manifests" in u])
    mirror.manifest("library/debian", "bullseye")
    second = len([u for u in hub.asked if "manifests" in u])
    assert second == first + 1, "a tag was served from cache"

    mirror.manifest("library/debian", digest)
    third = len([u for u in hub.asked if "manifests" in u])
    mirror.manifest("library/debian", digest)
    assert len([u for u in hub.asked if "manifests" in u]) == third, "a digest was refetched"


def test_the_pull_token_never_reaches_the_guest(tmp_path: Path) -> None:
    """Docker Hub needs one even anonymously. The host fetches it and attaches
    it upstream; it is not in anything the guest is served - the same rule the
    NVD key follows."""
    manifest = b'{"schemaVersion":2}'
    base = "https://registry-1.docker.io/v2/library/debian/manifests"
    mirror, hub = _mirror(tmp_path, {f"{base}/bullseye": manifest})
    body, _local, headers = mirror.route("/v2/library/debian/manifests/bullseye")
    assert b"token" not in (body or b"")
    assert not any("Authorization" in key for key in headers)
    assert any("auth.docker.io" in url for url in hub.asked), hub.asked


def test_the_step_the_docker_target_runs_is_wired_everywhere() -> None:
    """Four tables, and the broker refuses a step its own set omits."""
    import hashlib as _h

    import yaml

    from broker.registry import STEPS, resolve_step
    from xentry import generic
    from xentry.models import Facts

    root = Path(__file__).resolve().parents[1]
    steps = yaml.safe_load((root / "targets/steps.yaml").read_text())["steps"]
    spec = steps["setup-docker"]
    assert "setup-docker" in STEPS
    assert resolve_step("setup-docker").allowed_users == ("root",)
    script = root / "targets" / spec["script"]
    assert _h.sha256(script.read_bytes()).hexdigest() == spec["sha256"]
    # Positional: the index is the contract, and the shell variable it lands in
    # need not share the param's name - setup-generic's first arg is
    # apt_proxy_url and its variable is proxy_url. So what has to hold is that
    # every index is read and none beyond the list is.
    text = script.read_text()
    for index in range(1, len(spec["params"]) + 1):
        assert f'"${{{index}' in text, f"arg {index} ({spec['params'][index - 1]}) is never read"
    beyond = len(spec["params"]) + 1
    assert f'"${{{beyond}' not in text, f"it reads arg {beyond}, which the manifest does not pass"

    def facts(**kw: Any) -> Facts:
        base = {
            "cve_id": "CVE-2021-41773", "product": "Apache",
            "affected_range": "2.4.49", "version_evidence": [], "protocol": "http",
            "ports": [8080], "auth_required": False, "build_strategy": "",
            "poc_context": "remote", "citations": [], "poc_entrypoint": "exploit.py",
        }
        base.update(kw)
        return Facts(**base)  # type: ignore[arg-type]

    # A Dockerfile target uses a different STEP, not a flag on the apt one:
    # it installs nothing from the dated archive and must not be confusable
    # with a target that did.
    # A Dockerfile is itself a statement of how the software is installed, so it
    # admits a facts set that names no package - which is the one thing a
    # docker target never names.
    docker = generic.derive(facts(dockerfile=""), "https://github.com/o/r")
    assert docker.setup_step_id == "setup-docker"
    # Without one, the same facts are refused for naming no way to install
    # anything; with a package they take the apt step.
    with pytest.raises(generic.NoObservable, match="how to install"):
        generic.derive(facts(), "https://github.com/o/r")
    apt = generic.derive(facts(setup_packages=["apache2"]), "https://github.com/o/r")
    assert apt.setup_step_id == "setup-generic"
