"""Ask a model to write the PoC, for the experimental pipeline.

Everywhere else the PoC is pinned: a repository and a commit someone chose, or
a tarball whose bytes are recorded. Here a model writes it from the advisory
text, so there is no pin at all - which is why this runs only under /experiments
and its jobs never appear in the job list.

What does not change is the boundary. The generated file is staged with its
digest and run by the same checked-in step, as the same unprivileged actor, in
the same disposable attacker VM on the same isolated network. Running a
stranger's exploit from GitHub already had that posture; what differs here is
provenance, not privilege.

What also does not change is the evidence. The nonce is placed by the broker on
the *target*, is never shown to this model, and the generated code cannot print
a value it was never given unless it really read that file - so a fabricated
success is not available to it. The control run still has to come up empty.
"""

from __future__ import annotations

import os
import re

import litellm

from xentry import transcript
from xentry.models import Facts

FENCE_RE = re.compile(r"```(?:python|py)?\s*(.*?)```", re.DOTALL)
MAX_POC_BYTES = 40_000
# A refusal or an apology is not a PoC; it would be written to disk, fail to
# run, and look like a broken exploit rather than a model that declined.
MIN_POC_LINES = 5


class PocGenError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _prompt(cve_text: str, facts: Facts, target_ip_hint: str, previous: str) -> str:
    retry = ""
    if previous:
        retry = (
            "\nA previous attempt failed. Its output was:\n"
            f"{previous[-3000:]}\n"
            "Write a different approach; do not repeat the same mistake.\n"
        )
    return (
        "You are writing a single self-contained Python 3 exploit script for a "
        "disposable lab VM. Return only code, no prose and no markdown fence.\n"
        "The script is run as:  python3 exploit.py <target_ip> <port> <file_path>\n"
        "It must attempt to read <file_path> from the target over the network by "
        "exploiting the vulnerability below, and print whatever it reads to "
        "stdout. Print nothing else on success.\n"
        "Only the standard library is available plus the 'requests' package. "
        "There is no internet access. Exit non-zero if the attempt fails.\n"
        f"Target address: {target_ip_hint}\n"
        f"CVE: {facts.cve_id}\n"
        f"Product: {facts.product}\n"
        f"Affected: {facts.affected_range}\n"
        f"Protocol: {facts.protocol}  Ports: {facts.ports}\n"
        f"Authentication required: {facts.auth_required}\n"
        f"{retry}\n"
        "Advisory text follows.\n"
        "-----\n"
        f"{cve_text[:12000]}\n"
    )


def _strip_fence(content: str) -> str:
    fenced = FENCE_RE.search(content)
    return (fenced.group(1) if fenced else content).strip()


def author(
    cve_text: str,
    facts: Facts,
    target_ip_hint: str,
    previous: str = "",
) -> str:
    """One model call returning one Python file, or a refusal to proceed."""
    model = os.environ.get("XENTRY_POC_MODEL")
    if not model:
        raise PocGenError("provider_unavailable", "XENTRY_POC_MODEL is not set")
    # llama.cpp's server speaks the OpenAI chat API and ignores the key, but
    # litellm requires one to be present, so a placeholder is the default.
    api_key = os.environ.get("XENTRY_POC_API_KEY") or "sk-local"
    api_base = os.environ.get("XENTRY_POC_API_BASE") or None
    prompt = _prompt(cve_text, facts, target_ip_hint, previous)
    try:
        response = litellm.completion(
            model=model,
            api_key=api_key,
            api_base=api_base,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            timeout=600,
        )
    except Exception as exc:
        transcript.record("pocgen", prompt, f"provider_unavailable: {exc}")
        raise PocGenError("provider_unavailable", str(exc)) from exc
    content = (response.choices[0].message.content or "").strip()
    # Captured before any check, so a refusal stays inspectable as evidence.
    transcript.record("pocgen", prompt, content)
    code = _strip_fence(content)
    body = code.encode("utf-8")
    if len(body) > MAX_POC_BYTES:
        raise PocGenError("poc_rejected", f"generated PoC is {len(body)} bytes")
    lines = [line for line in code.splitlines() if line.strip()]
    if len(lines) < MIN_POC_LINES:
        raise PocGenError("poc_rejected", f"model returned {len(lines)} lines, not a script")
    if "import" not in code and "print" not in code:
        raise PocGenError("poc_rejected", "generated text does not look like a script")
    return code + "\n"
