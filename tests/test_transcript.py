"""Model transcripts are captured for the audit page, minus the nonce."""

from __future__ import annotations

from xentry import transcript


def _collect() -> tuple[list[tuple[str, str, str]], None]:
    seen: list[tuple[str, str, str]] = []
    transcript.set_sink(lambda stage, prompt, response: seen.append((stage, prompt, response)))
    return seen, None


def test_no_sink_is_a_no_op() -> None:
    transcript.set_sink(None)
    transcript.record("extract", "prompt", "response")  # must not raise


def test_sink_receives_stage_prompt_and_response() -> None:
    seen, _ = _collect()
    try:
        transcript.record("extract", "the question", "the answer")
    finally:
        transcript.set_sink(None)
    assert seen == [("extract", "the question", "the answer")]


def test_registered_secret_is_redacted_from_both_sides() -> None:
    nonce = "s3cr3t-nonce-value"
    transcript.add_secret(nonce)
    seen, _ = _collect()
    try:
        transcript.record("validate", f"prompt holding {nonce}", f"reply holding {nonce}")
    finally:
        transcript.set_sink(None)
    _stage, prompt, response = seen[0]
    assert nonce not in prompt
    assert nonce not in response
    assert "[REDACTED]" in prompt
    assert "[REDACTED]" in response


def test_empty_secret_is_ignored() -> None:
    transcript.add_secret("")
    seen, _ = _collect()
    try:
        transcript.record("extract", "unchanged", "unchanged")
    finally:
        transcript.set_sink(None)
    assert seen[0][1] == "unchanged"


def test_a_failing_sink_never_breaks_the_job() -> None:
    def explode(stage: str, prompt: str, response: str) -> None:
        raise RuntimeError("disk full")

    transcript.set_sink(explode)
    try:
        transcript.record("extract", "prompt", "response")  # must swallow
    finally:
        transcript.set_sink(None)


def test_a_sink_only_serves_the_thread_that_installed_it() -> None:
    """Why job 1d943b946bb6's extract prompt stopped matching its digest.

    The sink is a module global that writes into the running job's attempt
    directory. The web app calls the extractor from a request thread when links
    are checked, so without this guard that prompt was written as the running
    job's evidence - and record_artifact then raised on the runner's
    thread-bound sqlite connection, leaving a file with no row and a digest
    that no longer matched.
    """
    import threading

    from xentry import transcript

    seen: list[tuple[str, str, str]] = []
    transcript.set_sink(lambda stage, prompt, response: seen.append((stage, prompt, response)))
    try:
        transcript.record("extract", "mine", "ok")
        assert len(seen) == 1

        def from_another_thread() -> None:
            transcript.record("extract", "someone else's job", "ok")

        worker = threading.Thread(target=from_another_thread)
        worker.start()
        worker.join(timeout=5)
        assert len(seen) == 1, "a call from another thread must record nothing"
    finally:
        transcript.set_sink(None)
    transcript.record("extract", "after clearing", "ok")
    assert len(seen) == 1
