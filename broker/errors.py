"""Shared broker error type."""

from __future__ import annotations


class BrokerError(RuntimeError):
    """A broker call was rejected or failed."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
