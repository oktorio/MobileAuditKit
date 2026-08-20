from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "pin", "otp", "token", "access_token",
    "refresh_token", "authorization", "cookie", "session", "secret", "api_key",
    "apikey", "private_key", "account_number", "card_number", "cvv", "cvc",
    "plaintext", "ciphertext", "key_material", "iv", "nonce",
}

TOKEN_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{4,})?\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"(?i)\b(otp|pin)\s*[:=]?\s*\d{4,8}\b"), "[REDACTED_AUTH_VALUE]"),
]


def redact_text(value: str) -> str:
    result = value
    for pattern, replacement in TOKEN_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact(value: Any, key: str | None = None) -> Any:
    """Recursively redact sensitive values before output or persistence."""
    if key and key.lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value
