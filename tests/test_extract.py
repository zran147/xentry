"""Extractor citation and parsing tests."""

from __future__ import annotations

import hashlib

import pytest

from xentry.extract import ArtifactText, ExtractorError, _parse_json, verify_facts
from xentry.models import EvidenceRef, Facts


def _facts(quote: str) -> Facts:
    text = "CVE-2026-109618\nAffected Versions: PHP 8.4.0 ~ 8.4.26\n"
    sha = hashlib.sha256(text.encode()).hexdigest()
    ref = EvidenceRef(artifact_id="a", sha256=sha, quote=quote, line_start=1, line_end=1)
    return Facts(
        cve_id="CVE-2026-109618",
        product="PHP",
        affected_range="8.4.0 ~ 8.4.26",
        version_evidence=[ref],
        protocol="http",
        ports=[],
        auth_required=False,
        build_strategy="mod_php",
        poc_context="remote",
        citations=[ref],
    )


def test_citation_must_appear_in_artifact() -> None:
    text = "CVE-2026-109618\nAffected Versions: PHP 8.4.0 ~ 8.4.26\n"
    artifact = ArtifactText("a", hashlib.sha256(text.encode()).hexdigest(), text)
    verify_facts(_facts("Affected Versions: PHP 8.4.0 ~ 8.4.26"), [artifact])
    with pytest.raises(ExtractorError) as exc:
        verify_facts(_facts("Affected Versions: PHP 8.4.27"), [artifact])
    assert exc.value.code == "evidence_insufficient"


def test_fenced_json_is_parsed() -> None:
    assert _parse_json('```json\n{"cve_id":"CVE-2026-109618"}\n```')["cve_id"] == "CVE-2026-109618"
    assert _parse_json('prefix {"cve_id":"CVE-2026-109618"} suffix')["cve_id"] == "CVE-2026-109618"
    with pytest.raises(ExtractorError):
        _parse_json("not json at all")
