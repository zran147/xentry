"""Tests for the artifact research/pin helpers."""

from __future__ import annotations

import pytest

from xentry.artifact_tools import (
    extract_hashes,
    extract_urls,
    parse_deb822,
    parse_sha256sums,
    validate_sha256,
)


def test_validate_sha256() -> None:
    digest = "a" * 64
    assert validate_sha256(digest) == digest
    with pytest.raises(ValueError):
        validate_sha256("A" * 64)
    with pytest.raises(ValueError):
        validate_sha256("short")


def test_parse_sha256sums() -> None:
    text = "\n".join(
        [
            "b" * 64 + "  ubuntu-24.04-server-cloudimg-amd64.img",
            "# comment",
            "not-a-hash  other.iso",
        ]
    )
    assert parse_sha256sums(text) == {"ubuntu-24.04-server-cloudimg-amd64.img": "b" * 64}


def test_extract_hashes_and_urls() -> None:
    text = "sha256: " + "c" * 64 + " url https://example.com/a.deb"
    assert extract_hashes(text) == ["c" * 64]
    assert extract_urls(text) == ["https://example.com/a.deb"]


def test_parse_deb822() -> None:
    text = (
        "Package: example\n"
        "Version: 1.0\n"
        "Description: first line\n"
        " continued line\n"
        "\n"
        "Package: other\n"
        "Version: 2.0\n"
    )
    entries = parse_deb822(text)
    assert len(entries) == 2
    assert entries[0]["Package"] == "example"
    assert entries[0]["Version"] == "1.0"
    assert entries[1]["Package"] == "other"
