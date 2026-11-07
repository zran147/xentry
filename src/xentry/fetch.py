"""SSRF-safe fetching for CVE and PoC links."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

USER_AGENT = "xentry-fetch/0.1"
MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5


class FetchError(RuntimeError):
    """The URL was rejected or the fetch failed."""


@dataclass(frozen=True)
class Fetched:
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
            text=body.decode("utf-8", "replace"),
            sha256=hashlib.sha256(body).hexdigest(),
        )
    raise FetchError("too many redirects")


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
