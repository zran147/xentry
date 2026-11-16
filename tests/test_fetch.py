"""SSRF and fetch tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

from xentry.fetch import (
    Fetched,
    FetchError,
    artifact_text,
    bundle_sha256,
    cve_source_url,
    fetch,
    fetch_cve_enrichment,
    fetch_cve_evidence,
    fetch_poc_evidence,
    html_to_text,
    json_to_text,
    poc_source_url,
    resolve_public,
)


def test_private_and_non_http_urls_are_rejected() -> None:
    for url in (
        "file:///etc/passwd",
        "ftp://example.com/a",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
    ):
        with pytest.raises(FetchError):
            resolve_public(url)


def test_public_literal_is_accepted() -> None:
    scheme, port, host, address = resolve_public("http://8.8.8.8/")
    assert (scheme, port, host, address) == ("http", 80, "8.8.8.8", "8.8.8.8")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/body")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"hello xentry")

    def log_message(self, *args: object) -> None:
        return


def test_fetch_reads_body_and_follows_validated_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    monkeypatch.setattr(
        "xentry.fetch.resolve_public",
        lambda url: ("http", port, "localhost", "127.0.0.1"),
    )
    try:
        result = fetch(f"http://localhost:{port}/redirect")
        assert result.status == 200
        assert result.text == "hello xentry"
        assert result.final_url.endswith("/body")
        assert len(result.sha256) == 64
        assert len(bundle_sha256([result])) == 64
    finally:
        server.shutdown()
        server.server_close()


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
CVE_ORG_API = "https://cveawg.mitre.org/api/cve/"


@pytest.mark.parametrize(
    "url",
    [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-85706",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-85706/",
        "https://nvd.nist.gov/vuln/detail/cve-2026-85706",
        "https://www.nvd.nist.gov/vuln/detail/CVE-2026-85706",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-85706?query=1",
    ],
)
def test_nvd_detail_pages_resolve_to_the_json_record(url: str) -> None:
    # The detail page is rendered client-side, so fetching it returns an app
    # shell with no CVE data in it: 5,658 bytes with the CVE id appearing zero
    # times. It resolves to CVE Services rather than NVD's own API because NVD
    # throttles anonymous callers to five requests per thirty seconds and
    # answers 503; NVD stays the fallback, which fetch_cve_evidence walks.
    assert cve_source_url(url) == CVE_ORG_API + "CVE-2026-85706"


@pytest.mark.parametrize(
    "url",
    [
        "https://www.cve.org/CVERecord?id=CVE-2026-126187",
        "https://cve.org/CVERecord?id=CVE-2026-126187",
        "https://www.cve.org/CVERecord?id=cve-2026-126187&other=1",
    ],
)
def test_cve_org_record_pages_resolve_to_the_json_record(url: str) -> None:
    # A GET of the record page returns 880 bytes saying JavaScript is required,
    # with the CVE id nowhere in the markup - so the extractor has nothing to
    # cite and the job dies as evidence_insufficient. The id is in the query
    # string, not the path.
    assert cve_source_url(url) == CVE_ORG_API + "CVE-2026-126187"


def test_a_cve_org_page_with_no_id_is_left_alone() -> None:
    for url in ("https://www.cve.org/", "https://www.cve.org/CVERecord?id=notacve"):
        assert cve_source_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
        "https://raw.githubusercontent.com/o/r/abc123/README.md",
        "https://nvd.nist.gov/",
        "https://nvd.nist.gov/general/news",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-85706",
        "https://example.com/vuln/detail/CVE-2026-85706",
        "https://cveawg.mitre.org/api/cve/CVE-2026-126187",
        "https://example.com/CVERecord?id=CVE-2026-126187",
    ],
)
def test_other_urls_are_passed_through_untouched(url: str) -> None:
    assert cve_source_url(url) == url


class HeaderHandler(BaseHTTPRequestHandler):
    seen: ClassVar[dict[str, str]] = {}

    def do_GET(self) -> None:
        type(self).seen = {key.lower(): value for key, value in self.headers.items()}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args: object) -> None:
        return


def _headers_sent(monkeypatch: pytest.MonkeyPatch, host: str, key: str | None) -> dict[str, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), HeaderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    monkeypatch.setattr(
        "xentry.fetch.resolve_public",
        lambda url: ("http", port, host, "127.0.0.1"),
    )
    if key is None:
        monkeypatch.delenv("XENTRY_NVD_API_KEY", raising=False)
    else:
        monkeypatch.setenv("XENTRY_NVD_API_KEY", key)
    HeaderHandler.seen = {}
    try:
        fetch(f"http://{host}:{port}/rest/json/cves/2.0?cveId=CVE-2026-85706")
        return dict(HeaderHandler.seen)
    finally:
        server.shutdown()
        server.server_close()


def test_api_key_is_sent_to_the_nvd_api(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _headers_sent(monkeypatch, "services.nvd.nist.gov", "secret-key")
    assert sent.get("apikey") == "secret-key"


def test_api_key_is_withheld_from_other_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    # Checked per redirect hop, so a redirect off NVD cannot carry the key away.
    sent = _headers_sent(monkeypatch, "example.com", "secret-key")
    assert "apikey" not in sent


def test_no_api_key_sends_no_header(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _headers_sent(monkeypatch, "services.nvd.nist.gov", None)
    assert "apikey" not in sent


def test_api_key_cannot_splice_extra_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _headers_sent(monkeypatch, "services.nvd.nist.gov", "abc\r\nX-Injected: 1")
    assert "apikey" not in sent
    assert "x-injected" not in sent


def test_a_rendered_page_reaches_the_extractor_as_text() -> None:
    """The extractor sees the first MAX_ARTIFACT_CHARS of an artifact.

    A GitHub repository page is ~273 KB of markup whose README begins past
    character 120,000, so a 12,000-character budget bought dns-prefetch links
    and stylesheets. The extractor then truthfully reported that no port was in
    its evidence.
    """
    markup = (
        "<html><head><style>.a{color:red}</style>"
        "<script>var x = 'port 9999';</script></head>"
        "<body><!-- hidden --><h1>PoC</h1>"
        "<p>Serves on &lt;http://127.0.0.1:3100&gt;</p></body></html>"
    )
    text = html_to_text(markup)
    assert "3100" in text
    assert "color:red" not in text
    assert "9999" not in text
    assert "hidden" not in text
    assert "<" not in text.replace("<http", "")


def test_markdown_is_not_stripped() -> None:
    # A README writes <target_ip>; a tag stripper would silently eat it.
    body = b"# PoC\n\nRun: python3 exploit.py <target_ip> 8080\n"
    headers = {"content-type": "text/plain; charset=utf-8"}
    assert "<target_ip>" in artifact_text(headers, body)
    html = {"content-type": "text/html; charset=utf-8"}
    assert "<target_ip>" not in artifact_text(html, b"<p>x <target_ip> y</p>")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://github.com/briskets/CVE-2026-126187-poc",
            "https://raw.githubusercontent.com/briskets/CVE-2026-126187-poc/HEAD/README.md",
        ),
        (
            "https://github.com/owner/repo/",
            "https://raw.githubusercontent.com/owner/repo/HEAD/README.md",
        ),
        (
            "https://github.com/owner/repo.git",
            "https://raw.githubusercontent.com/owner/repo/HEAD/README.md",
        ),
        (
            "https://github.com/owner/repo/tree/v1.2",
            "https://raw.githubusercontent.com/owner/repo/v1.2/README.md",
        ),
    ],
)
def test_a_repository_url_resolves_to_its_readme(url: str, expected: str) -> None:
    assert poc_source_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/../etc/passwd",
        "https://github.com/owner/../../x",
        "https://github.com/owner/repo/blob/main/poc.py",
        "https://github.com/owner",
        "https://gitlab.com/owner/repo",
        "https://raw.githubusercontent.com/owner/repo/HEAD/README.md",
    ],
)
def test_other_poc_urls_are_left_alone(url: str) -> None:
    assert poc_source_url(url) == url


def test_a_repository_with_no_readme_falls_back_to_the_page() -> None:
    seen: list[str] = []

    def fake(url: str) -> object:
        seen.append(url)
        if url.startswith("https://raw.githubusercontent.com/"):
            raise FetchError("HTTP status 404")
        return "page"

    assert fetch_poc_evidence("https://github.com/owner/repo", fake) == "page"  # type: ignore[arg-type]
    # Three requests now: the README, the page it falls back to, and the file
    # tree. The tree is asked for either way, and a fake that answers it with
    # something unparseable must cost the listing rather than the check.
    assert seen == [
        "https://raw.githubusercontent.com/owner/repo/HEAD/README.md",
        "https://github.com/owner/repo",
        "https://api.github.com/repos/owner/repo/git/trees/HEAD?recursive=1",
    ]


# ------------------------------------------------- advisory JSON as text ---


def test_a_record_becomes_one_citable_line_per_field() -> None:
    """Both advisory APIs serve one line of JSON, so every citation said line 1."""
    text = json_to_text(
        '{"cveMetadata":{"cveId":"CVE-2026-56290"},"containers":{"cna":'
        '{"affected":[{"versions":[{"version":"1.0-3.6.0","status":"affected"}]}]}}}'
    )
    assert text.splitlines() == [
        "cveMetadata.cveId: CVE-2026-56290",
        "containers.cna.affected[0].versions[0].version: 1.0-3.6.0",
        "containers.cna.affected[0].versions[0].status: affected",
    ]


def test_no_line_carries_json_punctuation_to_escape() -> None:
    """The failure this exists for.

    CVE-2026-56290 died with `validator_error` because the extractor quoted
    `"versions":[{"version":"1.0-3.6.0","status":"affected"}]` verbatim into a
    JSON string field and did not escape the inner quotes. A quotable line with
    no quotes in it cannot reproduce that.
    """
    raw = '{"affected":[{"versions":[{"version":"1.0-3.6.0","status":"affected"}]}]}'
    assert '"' in raw
    for line in json_to_text(raw).splitlines():
        assert '"' not in line


def test_a_body_that_is_not_json_is_returned_unchanged() -> None:
    assert json_to_text("# PoC for CVE-2026-1") == "# PoC for CVE-2026-1"
    assert json_to_text("[]") == "[]"


def test_a_json_content_type_is_rendered_and_html_still_is_too() -> None:
    body = b'{"cve":{"id":"CVE-2026-1"}}'
    assert artifact_text({"content-type": "application/json"}, body) == "cve.id: CVE-2026-1"
    assert artifact_text({"content-type": "text/plain"}, body) == body.decode()
    assert artifact_text({"content-type": "text/html"}, b"<p>hi</p>") == "hi"


def test_empty_and_null_fields_are_dropped_rather_than_cited() -> None:
    """A citation of `x: None` would be a quote of nothing."""
    text = json_to_text('{"a":null,"b":"","c":[],"d":{},"e":0,"f":false}')
    assert text.splitlines() == ["e: 0", "f: False"]


def test_a_parsed_response_reads_the_bytes_not_the_rendering() -> None:
    """The regression that rendering JSON introduced, in both places it bit.

    Fetched.text is a rendering for a reader. Two callers parsed it as JSON and
    swallowed the failure, so the apt resolver silently found no versions at
    all and every derived job silently lost its snapshot serial - which means
    provisioning from the broker's default, which for a recent CVE is usually
    the patched build.
    """
    import json

    from xentry import generic, release

    nvd = json.dumps(
        {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-1", "published": "2026-06-29T15:16:42.360"}}
            ]
        }
    ).encode()
    served = Fetched(
        url="https://api.launchpad.net/x",
        final_url="https://api.launchpad.net/x",
        status=200,
        headers={"content-type": "application/json"},
        body=json.dumps(
            {"entries": [{"binary_package_version": "2.4.58-1ubuntu8.8"}]}
        ).encode(),
        text="",
        sha256="",
    )
    rendered = Fetched(**{**served.__dict__, "text": artifact_text(served.headers, served.body)})
    assert "{" not in rendered.text, "the rendering is not JSON, which is the point"
    assert release.published_versions("apache2", "noble", lambda _url: rendered) == {
        "2.4.58-1ubuntu8.8"
    }
    # And the date is read out of the rendering, where the caller has it.
    assert (
        generic.advisory_published(artifact_text({"content-type": "application/json"}, nvd))
        == "2026-06-29T15:16:42.360"
    )


def test_the_publication_date_is_found_in_either_record_shape() -> None:
    """cve.org links reach CVE 5.x, which the old json.loads never handled."""
    from xentry import generic

    cve5 = "cveMetadata.datePublished: 2026-06-29T14:31:37.952Z\ncveMetadata.state: PUBLISHED"
    nvd = "vulnerabilities[0].cve.published: 2026-06-29T15:16:42.360"
    assert generic.advisory_published(cve5) == "2026-06-29T14:31:37.952Z"
    assert generic.advisory_published(nvd) == "2026-06-29T15:16:42.360"
    # A neighbouring date field is not the publication date.
    assert generic.advisory_published("cveMetadata.dateUpdated: 2026-10-08T04:47:28.097Z") == ""
    assert generic.advisory_published("a GitHub advisory page") == ""


# ------------------------------------------------ the advisory source order ---


def test_cve_services_is_tried_before_nvd() -> None:
    """Measured, not assumed: seven requests back to back to NVD gave one 200
    and six 503s, and the one success took 16.5 seconds. The same burst to
    cveawg gave seven 200s at about 1.1s each."""
    asked: list[str] = []

    def fake(url: str) -> object:
        asked.append(url)
        return "record"

    got = fetch_cve_evidence(
        "https://nvd.nist.gov/vuln/detail/cve-2022-26134", fake  # type: ignore[arg-type]
    )
    assert got == "record"
    assert asked == ["https://cveawg.mitre.org/api/cve/CVE-2022-26134"]


def test_nvd_is_the_fallback_when_cve_services_cannot_answer() -> None:
    asked: list[str] = []

    def fake(url: str) -> object:
        asked.append(url)
        if "cveawg" in url:
            raise FetchError("HTTP status 404")
        return "from nvd"

    got = fetch_cve_evidence("https://www.cve.org/CVERecord?id=CVE-2022-26134", fake)  # type: ignore[arg-type]
    assert got == "from nvd"
    assert [url.split("/")[2] for url in asked] == [
        "cveawg.mitre.org",
        "services.nvd.nist.gov",
    ]


def test_a_throttle_is_waited_out_and_anything_else_is_not() -> None:
    """503 is what NVD answers when throttling, so it is worth a short wait.
    A 404 is not: retrying it only delays the fallback."""
    waits: list[float] = []
    attempts: list[str] = []

    def throttled(url: str) -> object:
        attempts.append(url)
        if len(attempts) < 3:
            raise FetchError("HTTP status 503")
        return "eventually"

    got = fetch_cve_evidence(
        "https://nvd.nist.gov/vuln/detail/CVE-2022-26134", throttled, sleep=waits.append  # type: ignore[arg-type]
    )
    assert got == "eventually"
    assert len(attempts) == 3
    assert waits == [1.0, 3.0]

    missing: list[str] = []

    def absent(url: str) -> object:
        missing.append(url)
        raise FetchError("HTTP status 404")

    with pytest.raises(FetchError):
        fetch_cve_evidence(
            "https://nvd.nist.gov/vuln/detail/CVE-2022-26134", absent, sleep=waits.append  # type: ignore[arg-type]
        )
    # One attempt per source, no retries, no waiting.
    assert len(missing) == 2
    assert waits == [1.0, 3.0]


def test_a_url_with_no_cve_id_is_fetched_as_given() -> None:
    asked: list[str] = []

    def fake(url: str) -> object:
        asked.append(url)
        return "page"

    assert fetch_cve_evidence("https://example.com/advisory", fake) == "page"  # type: ignore[arg-type]
    assert asked == ["https://example.com/advisory"]


@pytest.mark.parametrize(
    "url",
    [
        "https://vendor.example/security/CVE-2022-26134.html",
        "https://jira.atlassian.com/browse/CONFSERVER-79000",
        "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "https://lists.apache.org/thread/CVE-2021-44228-notice",
    ],
)
def test_a_page_that_is_not_an_app_shell_is_fetched_as_pasted(url: str) -> None:
    """A regression I introduced and then found by being asked about it.

    Only nvd.nist.gov and cve.org are replaced, because those two serve no
    advisory: the pasted NVD page is 5,658 bytes with the CVE id appearing
    zero times, and the cve.org page is 880 bytes of "needs JavaScript". Any
    other page the operator chose IS the evidence - a vendor's own advisory is
    usually better than either database - and for a while this rewrote every
    URL that merely contained a CVE id.
    """
    asked: list[str] = []
    fetch_cve_evidence(url, lambda item: asked.append(item) or "page")  # type: ignore[arg-type,func-returns-value]
    assert asked == [url]


def test_the_two_app_shell_hosts_are_replaced_by_the_record() -> None:
    def record(asked: list[str]) -> object:
        def fake(item: str) -> str:
            asked.append(item)
            return "record"

        return fake

    for url in (
        "https://nvd.nist.gov/vuln/detail/CVE-2022-26134",
        "https://www.cve.org/CVERecord?id=CVE-2022-26134",
    ):
        asked: list[str] = []
        fetch_cve_evidence(url, record(asked))  # type: ignore[arg-type]
        assert asked == ["https://cveawg.mitre.org/api/cve/CVE-2022-26134"], url


def test_nvd_is_read_as_extra_evidence_and_never_as_a_dependency() -> None:
    """Making CVE Services primary cost something, and this is the repair.

    For CVE-2021-44228 NVD carries `attackVector: NETWORK` and a vector string
    with AV:N; the CNA record carries no metrics at all. With that signal gone
    the extractor answered `protocol: null`, and admission then has no port and
    no default to fall back on. So NVD is read as a second artifact - and when
    it is throttled the job loses evidence instead of failing.
    """
    asked: list[str] = []

    def answers(url: str) -> str:
        asked.append(url)
        return "nvd record"

    got = fetch_cve_enrichment("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", answers)  # type: ignore[arg-type]
    assert got == "nvd record"
    assert asked == [
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
    ]

    def throttled(_url: str) -> str:
        raise FetchError("HTTP status 503")

    # None, not an exception: the job proceeds with what the CNA record gave.
    assert fetch_cve_enrichment("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", throttled) is None  # type: ignore[arg-type]
    # And a page the operator chose is never enriched, because it was not
    # replaced in the first place.
    assert fetch_cve_enrichment("https://vendor.example/CVE-2021-44228.html", answers) is None  # type: ignore[arg-type]


def test_the_eight_source_slots_go_to_the_files_that_matter() -> None:
    """A repository's docs/ folder could crowd out the exploit.

    Tree order is alphabetical and only eight files are fetched, so widening
    the suffix list to markdown and C made this reachable: docs/a.md and
    docs/b.md would be read and exploit.py would not. CVE-2021-25646's reply
    said "poc.md (not supplied as text) holds the exploit" - the one artifact
    describing the attack was the one thing withheld - so markdown has to be
    fetched AND has to be ranked.
    """
    from xentry.fetch import _source_rank

    paths = [
        "docs/a.md",
        "docs/b.md",
        "lib/vendor/deep/x.py",
        "poc.md",
        "exploit.py",
        "Dockerfile",
        "docker-compose.yml",
        "src/util.c",
        "run.sh",
    ]
    order = [
        entry["path"]
        for entry in sorted(({"path": path} for path in paths), key=_source_rank)
    ]
    # Named for what it is, first; then what runs or builds; then the rest.
    assert order[0] == "exploit.py"
    assert order[1] == "poc.md"
    assert set(order[2:5]) == {"Dockerfile", "docker-compose.yml", "run.sh"}
    assert order[-2:] == ["docs/a.md", "docs/b.md"]
    # And a deep vendored tree loses to a shallow one of the same kind.
    assert order.index("src/util.c") < order.index("lib/vendor/deep/x.py")
