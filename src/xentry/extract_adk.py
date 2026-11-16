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
        model=LiteLlm(model=model),
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
            text = ""
            content = getattr(final, "content", None)
            parts = getattr(content, "parts", None) or []
            if parts:
                text = getattr(parts[0], "text", "") or ""
            transcript.record("extract", prompt, text)
            facts = _validate(coerce_facts(_parse_json(text), artifacts))
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
