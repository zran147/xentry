"""Validator clamp tests."""

from __future__ import annotations

from xentry.models import LlmVerdict
from xentry.validator import NarrativeBundle, RunnerFacts, clamp_verdict


def _facts(**overrides: object) -> RunnerFacts:
    values = {
        "nonce_observed": True,
        "nonce_id": "n1",
        "nonce_sha256": "a" * 64,
        "null_actor_observed_nonce": False,
        "version_match": True,
        "precondition_ok": True,
        "vm_ids": ["vm-1"],
        "network_id": "net-1",
        "probe_evidence_sha256": "b" * 64,
    }
    values.update(overrides)
    return RunnerFacts(**values)


def test_reproduced_is_clamped_without_nonce() -> None:
    verdict = LlmVerdict(
        verdict="reproduced",
        reason_code="ok",
        evidence_refs=["e1"],
        explanation="looks good",
    )
    clamped = clamp_verdict(verdict, _facts(nonce_observed=False))
    assert clamped.verdict == "not_reproduced"
    assert clamped.reason_code == "nonce_not_observed"


def test_reproduced_is_clamped_without_version_match() -> None:
    verdict = LlmVerdict(
        verdict="reproduced",
        reason_code="ok",
        evidence_refs=["e1"],
        explanation="looks good",
    )
    clamped = clamp_verdict(verdict, _facts(version_match=False))
    assert clamped.verdict == "inconclusive"
    assert clamped.reason_code == "version_unidentified"


def test_reproduced_survives_runner_facts() -> None:
    verdict = LlmVerdict(
        verdict="reproduced",
        reason_code="ok",
        evidence_refs=["e1"],
        explanation="looks good",
    )
    assert clamp_verdict(verdict, _facts()).verdict == "reproduced"


def test_narrative_bundle_type() -> None:
    bundle = NarrativeBundle("poc", "setup", "transcript", "response")
    assert bundle.host_evidence_excerpt == ""
