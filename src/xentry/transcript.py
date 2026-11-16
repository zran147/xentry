"""Capture of the model calls a job makes, for the audit page."""

# Only a sha256 of the validator prompt used to be recorded, so there was no way
# to see what was asked or answered. The runner installs a sink for the attempt
# it is running and the extractor and validator hand their prompt and raw reply
# to it. Nonces are registered here as they are created and removed from every
# captured text before it is written, because a transcript is stored on disk and
# the nonce value must not be.

from __future__ import annotations

import threading
from collections.abc import Callable

from xentry.security import redact

Sink = Callable[[str, str, str], None]

# Per thread, not per process. A sink belongs to the job one worker is running
# and writes into that job's attempt directory, so it must not be visible to
# any other thread: the web app calls the extractor from a request thread when
# links are checked, and a second worker runs a second job.
_state = threading.local()
_secrets: set[str] = set()


def set_sink(sink: Sink | None) -> None:
    _state.sink = sink


def add_secret(value: str) -> None:
    # Registered values are redacted from every later capture. The set is
    # process-wide and never cleared: over-redacting a stale nonce is harmless,
    # leaking a live one is not.
    if value:
        _secrets.add(value)


def record(stage: str, prompt: str, response: str) -> None:
    # No sink on this thread means nothing to record: a link check in a request
    # thread used to be filed as the running job's evidence, and its
    # record_artifact then raised on the runner's thread-bound sqlite
    # connection, leaving a written file with no row and a digest that no
    # longer matched.
    sink: Sink | None = getattr(_state, "sink", None)
    if sink is None:
        return
    secrets = sorted(_secrets, key=len, reverse=True)
    try:
        sink(stage, redact(prompt, secrets), redact(response, secrets))
    except Exception:  # noqa: BLE001 - capture is never allowed to fail a job
        return
