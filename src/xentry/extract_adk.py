"""ADK extractor: one agent, no tools, typed output."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.runners import InMemoryRunner
from google.genai import types

from xentry import transcript
from xentry.extract import (
    JSON_ONLY,
    ArtifactText,
    ExtractorError,
    _parse_json,
    _prompt,
    coerce_facts,
    verify_facts,
)
from xentry.models import Facts


def _validate(payload: dict[str, Any]) -> Facts:
    """A reply that does not fit the schema is not an unavailable provider.

    The blanket `except Exception` below turned every pydantic ValidationError
    into "provider_unavailable: ADK extractor failed: 1 validation error for
    Facts ...", which points the reader at the network when the provider
    answered perfectly well and the reply was simply shaped wrong.
    """
    try:
        return Facts.model_validate(payload)
    except Exception as exc:
        raise ExtractorError(
            "evidence_insufficient", f"the reply does not fit the facts schema: {exc}"
        ) from exc


async def _run(artifacts: list[ArtifactText]) -> Facts:
    model = os.environ.get("XENTRY_EXTRACTOR_MODEL") or os.environ.get(
        "XENTRY_VALIDATOR_MODEL", "deepseek/deepseek-chat"
    )
    agent = LlmAgent(
        name="xentry_extractor",
        model=LiteLlm(model=model, **JSON_ONLY),
        instruction=(
            "Extract only the requested facts from the supplied artifacts. "
            "Return one JSON object with the requested keys. Never invent a quote or hash. "
            "Return JSON only, with no markdown."
        ),
        tools=[],
    )
    app_name = "xentry"
    user_id = "xentry"
    session_id = uuid.uuid4().hex
    runner = InMemoryRunner(agent=agent, app_name=app_name)
    prompt = _prompt(artifacts)
    try:
        await runner.session_service.create_session(
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
        )
        final: Any = None
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=types.Content(
                role="user",
                parts=[types.Part(text=prompt)],
            ),
        ):
            if event.is_final_response():
                final = event
        if final is None:
            raise ExtractorError("validator_error", "ADK returned no final event")
        output = getattr(final, "output", None)
        # Captured before validation so a rejected reply stays inspectable.
        if isinstance(output, Facts):
            transcript.record("extract", prompt, output.model_dump_json(indent=2))
            facts = output
        elif isinstance(output, dict):
            transcript.record("extract", prompt, json.dumps(output, indent=2, sort_keys=True))
            facts = _validate(coerce_facts(output, artifacts))
        else:
            content = getattr(final, "content", None)
            parts = getattr(content, "parts", None) or []
            # parts[0] WAS the answer, until the account moved to a reasoning
            # model. ADK turns a provider's reasoning into Part(thought=True)
            # and puts it first, so parts[0] became 11,754 characters of the
            # model thinking its way through sudo CVE-2025-32463 and ending
            # "Write JSON." - and the JSON it wrote next, in a later part, was
            # never read. deepseek-chat emitted no thought part, which is the
            # only reason this held up for as long as it did.
            #
            # The answer is every part that is NOT a thought; the thinking is
            # recorded under its own stage rather than thrown away, because it
            # is the only account of how a verdict was reached.
            text = "".join(p.text or "" for p in parts if not getattr(p, "thought", False))
            mind = "".join(p.text or "" for p in parts if getattr(p, "thought", False))
            transcript.record("extract.reasoning", prompt, mind)
            transcript.record("extract", prompt, text)
            # The event knows why it stopped and what it spent; this path threw
            # both away, so a truncated reply and a model that simply ended
            # read identically as "finish_reason=unknown".
            #
            # thoughts_token_count is the one that matters: DeepSeek charges
            # hidden reasoning against the same ceiling as the visible answer,
            # so a 2,500-token reply that stopped at "Final JSON." was either
            # the model finishing or 5,700 reasoning tokens pushing the total
            # into max_tokens - and only this number tells the two apart.
            use = getattr(final, "usage_metadata", None)
            why = (f"{getattr(final, 'finish_reason', '') or 'unknown'}, "
                   f"{getattr(use, 'candidates_token_count', '?')} visible + "
                   f"{getattr(use, 'thoughts_token_count', '?')} reasoning tokens")
            facts = _validate(coerce_facts(_parse_json(text, why), artifacts))
        verify_facts(facts, artifacts)
        return facts
    finally:
        await runner.close()


def adk_extract(artifacts: list[ArtifactText]) -> Facts:
    try:
        return asyncio.run(_run(artifacts))
    except ExtractorError:
        raise
    except Exception as exc:
        raise ExtractorError("provider_unavailable", f"ADK extractor failed: {exc}") from exc
