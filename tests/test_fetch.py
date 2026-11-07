"""SSRF and fetch tests."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from xentry.fetch import FetchError, bundle_sha256, fetch, resolve_public


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
