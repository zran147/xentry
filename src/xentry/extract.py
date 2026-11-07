"""CVE/PoC fact extraction.

The extractor sees only labeled excerpts and returns typed Facts with citations.
No tools, no fetch, no execute. The runner verifies every quote against the
artifact text before the facts can influence the plan.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

import litellm

from xentry.models import EvidenceRef, Facts

FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
MAX_ARTIFACT_CHARS = 12_000


class ExtractorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ArtifactText:
    artifact_id: str
    sha256: str
    text: str


def _numbered(text: str) -> str:
    return "\n".join(f"{index}: {line}" for index, line in enumerate(text.splitlines(), 1))


def _prompt(artifacts: list[ArtifactText]) -> str:
    blocks = []
    for artifact in artifacts:
        body = artifact.text[:MAX_ARTIFACT_CHARS]
        blocks.append(
            f"ARTIFACT {artifact.artifact_id} sha256={artifact.sha256}\n"
            f"{_numbered(body)}\n"
        )
    return (
        "You are the xentry extractor. Return exactly one JSON object and no markdown.\n"
        "Use only the supplied artifacts. Do not invent hashes, versions, ports, or quotes.\n"
        "Schema keys: cve_id, product, affected_range, version_evidence, protocol, ports, "
        "auth_required, build_strategy, poc_context, marker_candidate, artifact_candidates, "
        "citations.\n"
        "- cve_id: CVE-YYYY-NNNN or later digits.\n"
        "- product: the affected software product (for kernel advisories use "
        "\"Linux kernel\"), not the vulnerability nickname.\n"
        "- affected_range: the exact affected-version or version-range text; for "
        "kernel advisories include the kernel version (for example 6.17.0-23), "
        "not the vulnerability name.\n"
        "- version_evidence: array of objects exactly like "
        '{"artifact_id":"...","sha256":"...","quote":"...","line_start":1,"line_end":1}.\n'
        "- protocol: http, https, tcp, local, or null.\n"
        "- ports: array of integers.\n"
        "- auth_required: boolean.\n"
        "- build_strategy: short description.\n"
        "- poc_context: remote or local.\n"
        "- marker_candidate: optional short path or token.\n"
        "- artifact_candidates: array of the same evidence-ref objects for PoC/setup artifacts.\n"
        "- citations: array of the same evidence-ref objects; at least one.\n"
        "Every quote must be copied verbatim from the artifact text and must include "
        "artifact_id, sha256, and line numbers when possible. If the evidence is "
        "insufficient, return {\"error\": \"evidence_insufficient\"}.\n\n"
        + "\n".join(blocks)
    )


def _parse_json(content: str) -> dict[str, Any]:
    raw = content.strip()
    fenced = FENCE_RE.search(raw)
    if fenced:
        raw = fenced.group(1).strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}")
        if start < 0 or end <= start:
            raise ExtractorError("validator_error", "extractor returned no JSON object")
        try:
            parsed = json.loads(raw[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ExtractorError("validator_error", "extractor returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ExtractorError("validator_error", "extractor result is not an object")
    if parsed.get("error"):
        raise ExtractorError(str(parsed["error"]), "extractor reported insufficient evidence")
    return parsed


def _verify_refs(refs: list[EvidenceRef], texts: dict[str, ArtifactText]) -> None:
    for ref in refs:
        artifact = texts.get(ref.artifact_id)
        if artifact is None:
            raise ExtractorError("evidence_insufficient", f"unknown artifact: {ref.artifact_id}")
        if artifact.sha256 != ref.sha256:
            raise ExtractorError("evidence_insufficient", "artifact hash mismatch")
        if not ref.quote or ref.quote not in artifact.text:
            raise ExtractorError("evidence_insufficient", "citation quote not found in artifact")


def verify_facts(facts: Facts, artifacts: list[ArtifactText]) -> None:
    texts = {artifact.artifact_id: artifact for artifact in artifacts}
    _verify_refs(facts.version_evidence, texts)
    _verify_refs(facts.artifact_candidates, texts)
    _verify_refs(facts.citations, texts)


def direct_extract(artifacts: list[ArtifactText]) -> Facts:
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise ExtractorError("provider_unavailable", "DEEPSEEK_API_KEY is missing")
    model = os.environ.get("XENTRY_EXTRACTOR_MODEL") or os.environ.get(
        "XENTRY_VALIDATOR_MODEL", "deepseek/deepseek-chat"
    )
    try:
        response = litellm.completion(
            model=model,
            api_key=api_key,
            api_base=os.environ.get("DEEPSEEK_API_BASE"),
            messages=[{"role": "user", "content": _prompt(artifacts)}],
            temperature=0,
            timeout=120,
        )
    except Exception as exc:
        raise ExtractorError("provider_unavailable", str(exc)) from exc
    content = (response.choices[0].message.content or "").strip()
    parsed = _parse_json(content)
    try:
        facts = Facts.model_validate(parsed)
    except Exception as exc:
        raise ExtractorError("evidence_insufficient", f"facts schema failed: {exc}") from exc
    verify_facts(facts, artifacts)
    return facts


def extract(artifacts: list[ArtifactText], runtime: str | None = None) -> Facts:
    selected = runtime or os.environ.get("XENTRY_AGENT_RUNTIME", "litellm")
    if selected == "adk":
        # ADK is the production extractor. The direct call is the documented
        # fallback when the ADK path is unavailable (Gate F).
        try:
            from xentry.extract_adk import adk_extract

            return adk_extract(artifacts)
        except ExtractorError:
            raise
        except Exception as exc:
            raise ExtractorError("provider_unavailable", f"ADK extractor failed: {exc}") from exc
    return direct_extract(artifacts)
