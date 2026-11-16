"""A credential goes to exactly one host, and not one hop further."""

from __future__ import annotations

import pytest

from xentry import fetch as fetch_module


def _header(host: str, monkeypatch: pytest.MonkeyPatch, **env: str) -> str:
    for name in ("XENTRY_GITHUB_TOKEN", "XENTRY_NVD_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return fetch_module._api_key_header(host)


def test_the_token_reaches_the_github_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one host whose 60-per-hour limit is what caps a sweep.

    A check spends one request on the repository listing, so sixty CVEs
    exhaust the anonymous quota; after that every listing comes back empty and
    the extractor reports "the PoC text does not name a file that runs the
    exploit" about a file list it never read.
    """
    got = _header("api.github.com", monkeypatch, XENTRY_GITHUB_TOKEN="ghp_example")
    assert got == "Authorization: Bearer ghp_example\r\n"
    # Case in the Host header must not decide whether a credential is sent.
    assert _header("API.GitHub.com", monkeypatch, XENTRY_GITHUB_TOKEN="ghp_example")


def test_the_token_reaches_nobody_else(monkeypatch: pytest.MonkeyPatch) -> None:
    """Including GitHub's own other hosts.

    raw.githubusercontent.com and codeload serve public repositories under far
    looser limits, so a credential there widens its exposure and buys nothing.
    The advisory host is operator-supplied, which is the case that matters:
    fetch() is called with URLs this harness did not choose.
    """
    for host in (
        "raw.githubusercontent.com",
        "codeload.github.com",
        "github.com",
        "api.github.com.evil.test",
        "evil.test",
        "services.nvd.nist.gov",
    ):
        assert _header(host, monkeypatch, XENTRY_GITHUB_TOKEN="ghp_example") == "", host


def test_a_credential_cannot_splice_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    """CR or LF in the value would inject whole request headers.

    The request is assembled as a string and sent down a raw socket, so a
    newline in a token is not a malformed header - it is an attacker-chosen
    one. A pasted token with a trailing newline is also the likeliest way this
    ever happens by accident.
    """
    for bad in (
        "tok\r\nX-Injected: 1",
        "tok\nX-Injected: 1",
        "tok\rX-Injected: 1",
    ):
        assert _header("api.github.com", monkeypatch, XENTRY_GITHUB_TOKEN=bad) == ""
    # A surrounding newline is stripped rather than refused, so a token pasted
    # with a trailing newline still works.
    assert _header(
        "api.github.com", monkeypatch, XENTRY_GITHUB_TOKEN="  ghp_example\n"
    ) == "Authorization: Bearer ghp_example\r\n"


def test_the_nvd_key_still_works_and_stays_on_its_own_host(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two credentials now share one function; neither may reach the other's host."""
    both = {"XENTRY_NVD_API_KEY": "nvd_example", "XENTRY_GITHUB_TOKEN": "ghp_example"}
    assert _header("services.nvd.nist.gov", monkeypatch, **both) == "apiKey: nvd_example\r\n"
    assert _header("api.github.com", monkeypatch, **both) == (
        "Authorization: Bearer ghp_example\r\n"
    )


def test_no_credential_configured_sends_no_header(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _header("api.github.com", monkeypatch) == ""
    assert _header("services.nvd.nist.gov", monkeypatch) == ""
    assert _header("api.github.com", monkeypatch, XENTRY_GITHUB_TOKEN="   ") == ""


def test_a_citation_may_carry_the_prompt_s_own_line_numbers() -> None:
    """The verifier was defeated by the harness's own rendering.

    Every artifact reaches the model through _numbered(), and the same prompt
    says "copied verbatim from the artifact text" AND "Line numbers when
    possible". A model that does as it is told emits "51: containerd is an
    open-source container runtime", which is a substring of nothing.
    CVE-2024-40635 was refused on five such citations with a correct
    extraction behind them - poc_entrypoint "poc.py", and poc.py in the
    listing.
    """
    from xentry import extract

    text = "containerd is an open-source container runtime. A bug was found.\nsecond line"
    assert extract._quote_present("containerd is an open-source", text)
    assert extract._quote_present("51: containerd is an open-source", text)
    assert extract._quote_present(
        "51: containerd is an open-source container runtime. A bug was found.\n"
        "52: second line",
        text,
    )
    # A quote that is genuinely absent must still fail, numbering or not.
    assert not extract._quote_present("99: this text is absent", text)
    # And the raw form is tried first, so a quote that really begins with
    # digits and a colon still matches as itself rather than being stripped.
    assert extract._quote_present("80: tcp", "listen 80: tcp here")
