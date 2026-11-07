"""Secret handling and UI vocabulary tests."""

from __future__ import annotations

from pathlib import Path

from xentry.security import constant_time_equal, new_nonce, redact

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src" / "xentry" / "web"


def test_nonce_and_redaction() -> None:
    nonce = new_nonce()
    assert len(nonce) == 32
    assert redact(f"a {nonce} b", [nonce]) == "a [REDACTED] b"
    assert constant_time_equal("abc", "abc")
    assert not constant_time_equal("abc", "abd")


def test_ui_does_not_use_banned_words() -> None:
    banned = ("succeeded", "verified")
    for path in list((WEB / "templates").glob("*.html")) + list((WEB / "static").glob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").lower()
        for word in banned:
            assert word not in text, f"{path} contains banned word {word}"
