"""SSRF-safe fetching for CVE and PoC links.

Two advisory sites render in the browser and serve an empty shell to a plain
GET - nvd.nist.gov and cve.org. Both are rewritten to the API that serves the
same record as data, because an empty page is indistinguishable downstream from
an advisory that simply said little.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlsplit

USER_AGENT = "xentry-fetch/0.1"
MAX_BYTES = 2_000_000
# A PoC repository's tarball, which is not a page and is not bounded by the
# same reasoning. kozmer/log4j-shell-poc ships a prebuilt
# log4shell-1.0-SNAPSHOT.war and two jars, so its archive is over 2 MB and
# staging it failed with "response exceeds 2000000 bytes" - a harness_error
# with no mention of the repository's size. Screenshots, conference PDFs and
# demo videos put many PoC repositories over that line, so the default was
# refusing a large and ordinary class.
MAX_POC_BYTES = 64_000_000
MAX_REDIRECTS = 5
NVD_PAGE_HOSTS = frozenset({"nvd.nist.gov", "www.nvd.nist.gov"})
NVD_API_HOST = "services.nvd.nist.gov"
NVD_API_URL = f"https://{NVD_API_HOST}/rest/json/cves/2.0?cveId="
CVE_ORG_PAGE_HOSTS = frozenset({"cve.org", "www.cve.org"})
CVE_ORG_API_URL = "https://cveawg.mitre.org/api/cve/"
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
GITHUB_PAGE_HOSTS = frozenset({"github.com", "www.github.com"})
GITHUB_RAW_URL = "https://raw.githubusercontent.com/"
GITHUB_API_URL = "https://api.github.com/"
# A cap, because the tree is evidence for a model with a context window:
# kozmer's repository has 36 files, a vendored node_modules would have
# thousands, and the first few hundred paths are what says what this is.
MAX_TREE_ENTRIES = 300
# The repository's own small text files, read as well as listed. A PoC's port,
# its usage and its real filename live in its source far more often than in its
# README: CVE-2025-32433's README is a blog link and an image while `PORT =
# 2222` is line 6 of its exploit, CVE-2021-41773's port is `"8080:80"` in a
# compose file, and CVE-2022-29464's README misspells `exploit.py` in the one
# heading that names it. Six refusals in one session came down to facts that
# were sitting in files nobody read.
#
# Text only, small only, and capped three ways - per file, per repository and
# by count - because this is evidence for a model with a context window, not a
# checkout. Binary and archive suffixes are absent on purpose: a .deb or a .jar
# would be megabytes of nothing a reader can use.
POC_SOURCE_SUFFIXES = (
    ".py", ".sh", ".yml", ".yaml", ".conf", ".json", ".erl", ".go", ".rb",
    ".txt", ".cfg", ".ini", ".toml", ".env", ".service", ".xml",
    # Markdown besides the README, because in a repository that ships no
    # script the exploit IS the documentation: CVE-2021-25646's reply said
    # "poc.md (not supplied as text) holds the exploit" - the model could see
    # the filename in the listing and not its contents, so the one artifact
    # that described the attack was the one thing withheld from it.
    ".md", ".markdown", ".c", ".java", ".ps1", ".rs", ".php", ".js", ".ts",
)
POC_SOURCE_NAMES = ("Dockerfile", "Makefile", "docker-compose.yml", "requirements.txt")
MAX_SOURCE_FILES = 8
MAX_SOURCE_BYTES = 24_000
MAX_SOURCE_TOTAL = 80_000
GITHUB_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
GITHUB_REPO_RE = re.compile(r"^/([^/]+)/([^/]+?)(?:\.git)?/?$")
GITHUB_TREE_RE = re.compile(r"^/([^/]+)/([^/]+?)/tree/([^/]+)/?$")
HTML_TYPES = ("text/html", "application/xhtml+xml")
JSON_TYPES = ("application/json", "application/vnd.api+json", "text/json")
HIDDEN_RE = re.compile(r"<(script|style|template|svg|noscript)\b[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")


# In the order they are tried. CVE Services first, measured: seven requests
# back to back to NVD gave one 200 and six 503s, and the one success took 16.5
# seconds; the same burst to cveawg gave seven 200s at about 1.1s each. NVD
# throttles anonymous callers to five requests per rolling thirty seconds and
# answers 503 rather than 429, so a second CVE pasted inside half a minute
# simply fails. Both carry what the extractor needs; the CNA record carries the
# vendor's own affected-version list, which is usually better than NVD's
# analysis for this purpose.
CVE_SOURCES = (CVE_ORG_API_URL, NVD_API_URL)
# A throttle is transient, so it is worth waiting out; anything else is not.
RETRY_STATUSES = ("503", "429")
RETRY_DELAYS = (1.0, 3.0)


def fetch_cve_evidence(
    url: str,
    fetch_fn: Callable[[str], Fetched],
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> Fetched:
    """The advisory record, from whichever source answers.

    Being *less* identified does not help here and would be the wrong
    instinct: the limit is per source address, and anonymity is exactly what
    makes it five requests per thirty seconds instead of fifty.
    XENTRY_NVD_API_KEY raises NVD's share when it is set, but the real fix is
    not to depend on one throttled service for a record two of them publish.
    """
    # Only the two hosts that serve no advisory at all are replaced, which is
    # the discipline cve_source_url has always had and which this function
    # briefly lost: a URL was rewritten whenever it contained a CVE id, so a
    # vendor's own advisory page - often the best source there is - would have
    # been silently swapped for the database record. Anything else is fetched
    # as pasted, because the page the operator chose IS the evidence.
    rewritten = cve_source_url(url)
    if rewritten == url:
        return fetch_fn(url)
    found = CVE_ID_RE.search(rewritten)
    if found is None:
        return fetch_fn(url)
    cve_id = found.group(0).upper()
    last: FetchError | None = None
    for base in CVE_SOURCES:
        for delay in (*RETRY_DELAYS, None):
            try:
                return fetch_fn(base + cve_id)
            except FetchError as exc:
                last = exc
                if not any(code in str(exc) for code in RETRY_STATUSES):
                    break
                if delay is None:
                    break
                sleep(delay)
    assert last is not None
    raise last


def fetch_cve_enrichment(
    url: str, fetch_fn: Callable[[str], Fetched]
) -> Fetched | None:
    """NVD's record as well, when it answers. Best effort, never required.

    The two records are not interchangeable and making CVE Services primary
    cost something: NVD carries CVSS metrics and the CNA record often does
    not. For CVE-2021-44228 NVD has `attackVector: NETWORK` and a vector
    string with AV:N, and cveawg has neither - and with that signal gone the
    extractor answered `protocol: null`, which fails admission because there
    is then no port and no default to fall back on.

    So NVD is read as a second artifact rather than as the source. When it is
    throttled - five requests per thirty seconds, answered 503 - the job loses
    some evidence instead of failing, which is the right way round.
    """
    found = CVE_ID_RE.search(cve_source_url(url))
    if found is None or cve_source_url(url) == url:
        return None
    try:
        return fetch_fn(NVD_API_URL + found.group(0).upper())
    except FetchError:
        return None


def cve_source_url(url: str) -> str:
    # nvd.nist.gov renders /vuln/detail/<id> in the browser: a plain GET returns
    # the single-page-app shell for every path, carrying no CVE data at all and a
    # per-request CDN id in the markup. Its REST API serves the same record as
    # JSON, so no browser is needed, and the extractor receives the description,
    # CVSS metrics and affected-version configurations as fields rather than
    # prose. Every other URL is returned unchanged, so static advisory pages and
    # pinned raw files keep working as before.
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host in NVD_PAGE_HOSTS:
        match = CVE_ID_RE.search(parts.path)
        # CVE Services, not NVD's own API: see entry 23. Measured, seven
        # requests back to back gave NVD one 200 and six 503s. NVD remains the
        # fallback, which fetch_cve_evidence walks.
        return url if match is None else CVE_ORG_API_URL + match.group(0).upper()
    if host in CVE_ORG_PAGE_HOSTS:
        # cve.org is the same single-page-app problem as nvd.nist.gov, and worse:
        # a GET of /CVERecord?id=<ID> returns 880 bytes whose only readable text
        # is "the CVE Website doesn't work properly without JavaScript enabled",
        # with the id itself nowhere in the markup. The extractor then has
        # nothing to cite and the job fails as evidence_insufficient, which reads
        # like a thin advisory rather than a link that carried no advisory at all.
        # The CVE Services API serves the same record as CVE 5.x JSON - title,
        # descriptions, affected ranges, metrics and references as fields. The id
        # is in the query string here, not the path.
        match = CVE_ID_RE.search(f"{parts.path}?{parts.query}")
        return url if match is None else CVE_ORG_API_URL + match.group(0).upper()
    return url


def html_to_text(markup: str) -> str:
    """Readable text from a rendered page, so the extractor's budget buys evidence.

    The extractor sees only the first MAX_ARTIFACT_CHARS of each artifact. Raw
    markup spends that on <head>: a GitHub repository page is 273 KB of HTML
    whose README - the only part that states a port - begins at character
    120,918, so the extractor received dns-prefetch links and stylesheets and
    truthfully reported that no port was in its evidence. The same page as text
    is 11.9 KB with the port at character 5,574.

    Applied only to HTML. Markdown is left alone: a README writes <target_ip>
    and <your-ip>, and a tag stripper would silently eat them.
    """
    text = HIDDEN_RE.sub(" ", markup)
    text = COMMENT_RE.sub(" ", text)
    text = TAG_RE.sub(" ", text)
    text = unescape(text)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" ?\n ?", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _flatten(node: Any, prefix: str, out: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            _flatten(value, f"{prefix}.{key}" if prefix else str(key), out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _flatten(value, f"{prefix}[{index}]", out)
    elif node is not None and node != "":
        out.append(f"{prefix}: {node}")


def json_to_text(payload: str) -> str:
    """One `path: value` line per field, so an advisory record can be cited.

    Both advisory APIs serve a record as a single line of JSON, and that broke
    extraction twice over. Every citation came back as line 1 because there was
    only one line. Worse, asking for a verbatim quote out of a JSON document,
    to be returned inside a JSON string, invites the model to copy raw JSON
    punctuation: CVE-2026-56290 failed with `validator_error` on a quote of
    `"versions":[{"version":"1.0-3.6.0",...` whose unescaped quotes made the
    whole reply unparseable. A flattened line carries no JSON punctuation to
    escape and has a line number that means something.

    Deliberately schema-agnostic: NVD 2.0 and CVE 5.x nest differently and
    neither is parsed, so a schema change cannot silently drop a field. A body
    that is not JSON after all is returned unchanged rather than refused.
    """
    try:
        data = json.loads(payload)
    except ValueError:
        return payload
    out: list[str] = []
    _flatten(data, "", out)
    return "\n".join(out) if out else payload


def _github_repo(url: str) -> tuple[str, str, str] | None:
    """owner, repo and ref for a GitHub repository URL, or None."""
    parts = urlsplit(url)
    if (parts.hostname or "").lower() not in GITHUB_PAGE_HOSTS:
        return None
    match = GITHUB_REPO_RE.match(parts.path)
    ref = "HEAD"
    if match is None:
        match = GITHUB_TREE_RE.match(parts.path)
        if match is None:
            return None
        owner, repo, ref = match.group(1), match.group(2), match.group(3)
    else:
        owner, repo = match.group(1), match.group(2)
    if not all(GITHUB_SEGMENT_RE.match(part) for part in (owner, repo, ref)):
        return None
    return owner, repo, ref


def poc_source_url(url: str) -> str:
    # A GitHub repository URL names a page; the evidence is its README. The
    # pinned targets already fetch the raw README at their pinned commit - this
    # is the same for a repository nobody has pinned, so a derived target reads
    # the PoC's own instructions rather than GitHub's chrome. Not a claim about
    # provenance: the bytes are still hashed into the bundle, and the caller
    # falls back to the page itself if the repository has no README.md.
    found = _github_repo(url)
    if found is None:
        return url
    owner, repo, ref = found
    return f"{GITHUB_RAW_URL}{owner}/{repo}/{ref}/README.md"


def poc_file_url(url: str, path: str) -> str:
    """A raw URL for one file inside the PoC repository, or "".

    What the approval card offers when the gap is a file the PoC itself ships:
    the config that makes the affected software vulnerable, which no archive
    carries because it is not part of the package. Checked rather than
    formatted - a path with a separator trick in it would point the operator
    at someone else's repository.
    """
    found = _github_repo(url)
    raw = path.strip() if path else ""
    # Checked BEFORE anything is stripped, and removeprefix rather than
    # lstrip: lstrip takes a character set, so lstrip("./") turned
    # "../../etc/passwd" into "etc/passwd" and the ".." check never saw it.
    # GitHub would not have served anything outside the repository, but the
    # offered path would silently not have been the one the model named.
    if found is None or not raw or ".." in raw or raw.startswith("/"):
        return ""
    clean = raw.removeprefix("./")
    if not clean or not all(GITHUB_SEGMENT_RE.match(part) for part in clean.split("/")):
        return ""
    owner, repo, ref = found
    return f"{GITHUB_RAW_URL}{owner}/{repo}/{ref}/{clean}"


def poc_tree_url(url: str) -> str:
    """Every file in the repository, including subfolders, in one request.

    A README is not the repository. blasty's CVE-2021-41773 vendors four
    apache2_2.4.49-4 .debs and a 000-default.conf its README never mentions,
    and kozmer's log4j-shell-poc ships target/log4shell-1.0-SNAPSHOT.war - the
    vulnerable application already built - plus marshalsec as a jar. Both were
    refused for want of facts that were sitting in the tree. recursive=1 is
    what reaches a PoC in a subfolder, which a top-level listing would miss.
    """
    found = _github_repo(url)
    if found is None:
        return ""
    owner, repo, ref = found
    return f"{GITHUB_API_URL}repos/{owner}/{repo}/git/trees/{ref}?recursive=1"


def _poc_tree(url: str, fetch_fn: Callable[[str], Fetched]) -> tuple[list[Any], bool]:
    """Every file in the repository, and whether GitHub truncated the answer.

    Best effort, like the NVD enrichment: GitHub allows 60 unauthenticated
    requests an hour per address, and losing this costs evidence rather than
    failing a check.
    """
    api = poc_tree_url(url)
    if not api:
        return [], False
    try:
        payload = json.loads(fetch_fn(api).body)
    except (FetchError, ValueError, AttributeError):
        return [], False
    blobs = [
        entry
        for entry in (payload.get("tree") or [])[:MAX_TREE_ENTRIES]
        if isinstance(entry, dict) and entry.get("type") == "blob"
    ]
    return blobs, bool(payload.get("truncated"))


def _tree_listing(blobs: list[Any], truncated: bool) -> bytes:
    """The repository's files as `size path` lines."""
    lines = [f"{entry.get('size', 0)} {entry.get('path', '')}" for entry in blobs]
    if not lines:
        return b""
    head = "repository files (size path), every subfolder included:"
    if truncated:
        head = f"{head} TRUNCATED by GitHub, this is not every file:"
    return ("\n\n" + head + "\n" + "\n".join(lines) + "\n").encode("utf-8")


EXPLOIT_WORDS = ("exploit", "poc", "cve", "shell", "payload")


def _source_rank(entry: Any) -> tuple[int, int, str]:
    """Which files to spend the eight slots on, most promising first.

    Tree order is alphabetical, so a repository with a docs/ or lib/ folder
    could fill every slot before reaching the one file that runs the exploit.
    A name that says what it is comes first, then anything executable, then
    the rest - and within each group the shallowest path, since a lab's own
    vendored tree is deep.
    """
    path = str(entry.get("path") or "")
    name = path.rsplit("/", 1)[-1].lower()
    named = 0 if any(word in name for word in EXPLOIT_WORDS) else 1
    builds = {item.lower() for item in POC_SOURCE_NAMES}
    runnable = (
        0 if path.endswith((".py", ".sh", ".rb", ".c", ".go")) or name in builds else 1
    )
    return (named, runnable, f"{path.count('/')}{path}")


def _poc_sources(
    url: str, fetch_fn: Callable[[str], Fetched], blobs: list[Any]
) -> bytes:
    """The small text files themselves, each under its own heading."""
    out: list[bytes] = []
    spent = 0
    for entry in sorted(blobs, key=_source_rank):
        if len(out) >= MAX_SOURCE_FILES or spent >= MAX_SOURCE_TOTAL:
            break
        path = str(entry.get("path") or "")
        name = path.rsplit("/", 1)[-1]
        size = int(entry.get("size") or 0)
        # README.md is already the first artifact; including it twice would
        # spend the budget on text the model has read once.
        if name.lower() in {"readme.md", "readme"} or not path:
            continue
        if not (path.endswith(POC_SOURCE_SUFFIXES) or name in POC_SOURCE_NAMES):
            continue
        if size <= 0 or size > MAX_SOURCE_BYTES:
            continue
        raw = poc_file_url(url, path)
        if not raw:
            continue
        try:
            got = fetch_fn(raw)
        except FetchError:
            continue
        body = got.body[:MAX_SOURCE_BYTES]
        out.append(f"\n\n--- {path} ---\n".encode() + body)
        spent += len(body)
    return b"".join(out)


def fetch_poc_evidence(url: str, fetch_fn: Callable[[str], Fetched]) -> Fetched:
    """The PoC's README and the repository's file tree, as one artifact.

    Appended to the *body*, not just the rendered text, so the digest the
    bundle pins covers exactly what the extractor was shown.
    """
    raw = poc_source_url(url)
    if raw == url:
        return fetch_fn(url)
    try:
        readme = fetch_fn(raw)
    except FetchError:
        readme = fetch_fn(url)
    blobs, truncated = _poc_tree(url, fetch_fn)
    extra = _tree_listing(blobs, truncated) + _poc_sources(url, fetch_fn, blobs)
    if not extra:
        return readme
    body = readme.body + extra
    return replace(
        readme,
        body=body,
        text=artifact_text(dict(readme.headers), body),
        sha256=hashlib.sha256(body).hexdigest(),
    )


# Only api.github.com. raw.githubusercontent.com and codeload serve public
# repositories with far looser limits, so sending a credential there would widen
# its exposure and buy nothing.
GITHUB_API_HOST = "api.github.com"
# (name, host, template). Each is scoped to ONE host and re-evaluated per
# redirect hop, so a redirect elsewhere cannot carry a credential off-site;
# isprintable() rejects a value containing CR or LF, which would otherwise
# splice extra headers into the request.
#
# NVD allows 5 requests per 30 seconds anonymously and 50 with a key, so its key
# only matters once more than a few CVEs are submitted in a burst.
#
# GitHub allows 60 requests an hour PER ADDRESS unauthenticated, and a check
# spends one on the repository listing. A sweep of sixty CVEs therefore
# exhausts it, and every check after that reads an EMPTY listing - which the
# extractor reports as "the PoC text does not name a file that runs the
# exploit", a verdict about content for a file list never read. Measured on
# 2026-11-15: thirteen refusals of twenty-four carried that message after a
# screening script spent the hour's quota. A token raises the limit to 5,000.
_CREDENTIALS = (
    ("XENTRY_NVD_API_KEY", NVD_API_HOST, "apiKey: {}\r\n"),
    ("XENTRY_GITHUB_TOKEN", GITHUB_API_HOST, "Authorization: Bearer {}\r\n"),
)


def _api_key_header(host: str) -> str:
    for name, wanted, template in _CREDENTIALS:
        value = os.environ.get(name, "").strip()
        if value and value.isprintable() and host.lower() == wanted:
            return template.format(value)
    return ""


class FetchError(RuntimeError):
    """The URL was rejected or the fetch failed."""


@dataclass(frozen=True)
class Fetched:
    """One fetched source.

    ``body`` is the bytes as served and ``sha256`` is their digest; those are
    what the bundle pins. ``text`` is a rendering of them *for a reader* - HTML
    stripped to its prose, a JSON record flattened to one citable line per
    field - so anything that needs to parse the response must use ``body``.
    Two callers learned that the hard way: release.published_versions and
    generic.advisory_published both did json.loads(.text) and both swallowed
    the failure, so the apt resolver silently found no versions and every
    derived job silently lost its snapshot serial.
    """

    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    text: str
    sha256: str


def _public(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def resolve_public(url: str) -> tuple[str, int, str, str]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise FetchError(f"unsupported scheme: {parsed.scheme}")
    if parsed.username or parsed.password:
        raise FetchError("userinfo is not allowed")
    host = parsed.hostname
    if not host:
        raise FetchError("missing host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise FetchError("invalid port")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise FetchError(f"DNS resolution failed: {host}") from exc
        addresses = sorted({str(info[4][0]) for info in infos})
    if not addresses:
        raise FetchError(f"no addresses for {host}")
    for address in addresses:
        if not _public(ipaddress.ip_address(address)):
            raise FetchError(f"non-public address rejected: {address}")
    return parsed.scheme, port, host, addresses[0]


def _request_once(
    url: str,
    scheme: str,
    port: int,
    host: str,
    address: str,
    *,
    max_bytes: int,
    timeout: float,
) -> tuple[int, dict[str, str], bytes]:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    default_port = 443 if scheme == "https" else 80
    host_header = host if port == default_port else f"{host}:{port}"
    try:
        sock = socket.create_connection((address, port), timeout=timeout)
    except OSError as exc:
        raise FetchError(f"connect failed: {address}:{port}") from exc
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: text/html,text/plain,application/json;q=0.9,*/*;q=0.1\r\n"
            "Accept-Encoding: identity\r\n"
            f"{_api_key_header(host)}"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode("utf-8"))
        response = http.client.HTTPResponse(sock, method="GET")
        response.begin()
        status = response.status
        headers = {key.lower(): value for key, value in response.getheaders()}
        body = response.read(max_bytes + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise FetchError(f"request failed: {url}") from exc
    finally:
        sock.close()
    if len(body) > max_bytes:
        raise FetchError(f"response exceeds {max_bytes} bytes")
    if headers.get("content-encoding", "").lower() == "gzip":
        try:
            body = gzip.decompress(body)
        except OSError as exc:
            raise FetchError("invalid gzip response") from exc
        if len(body) > max_bytes:
            raise FetchError(f"decoded response exceeds {max_bytes} bytes")
    return status, headers, body


def fetch(url: str, *, max_bytes: int = MAX_BYTES, timeout: float = 20.0) -> Fetched:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        scheme, port, host, address = resolve_public(current)
        status, headers, body = _request_once(
            current,
            scheme,
            port,
            host,
            address,
            max_bytes=max_bytes,
            timeout=timeout,
        )
        if status in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            if not location:
                raise FetchError("redirect without location")
            current = urljoin(current, location)
            continue
        if status >= 400:
            raise FetchError(f"HTTP status {status}")
        return Fetched(
            url=url,
            final_url=current,
            status=status,
            headers=headers,
            body=body,
            text=artifact_text(headers, body),
            sha256=hashlib.sha256(body).hexdigest(),
        )
    raise FetchError("too many redirects")


def artifact_text(headers: dict[str, str], body: bytes) -> str:
    """How a fetched body is rendered for a reader. The one definition.

    It is public because `fetch` is not the only place a Fetched is built:
    sourcestore replays the bytes a link check approved, and for a while it
    rebuilt `text` as a plain decode. Everything downstream reads `text`, so
    on the replayed path - which is every real job - the extractor got raw
    JSON back and `advisory_published` found no date in it. The npm target
    refused outright; the apt path just quietly lost its snapshot serial.
    """
    decoded = body.decode("utf-8", "replace")
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type in HTML_TYPES:
        return html_to_text(decoded)
    if content_type in JSON_TYPES:
        return json_to_text(decoded)
    return decoded


def bundle_sha256(items: list[Fetched]) -> str:
    canonical = [
        {
            "url": item.url,
            "final_url": item.final_url,
            "status": item.status,
            "sha256": item.sha256,
        }
        for item in items
    ]
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
