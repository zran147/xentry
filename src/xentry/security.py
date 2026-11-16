"""Small helpers for secrets, redaction, and constant-time checks."""

from __future__ import annotations

import hmac
import re
import secrets

NONCE_RE = re.compile(r"\b[0-9a-f]{32,128}\b")


def new_nonce() -> str:
    return secrets.token_hex(16)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def redact(text: str, values: list[str]) -> str:
    for value in values:
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
