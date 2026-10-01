from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "pin", "otp", "token", "accesstoken", "refreshtoken",
    "authorization", "cookie", "session", "secret", "apikey", "privatekey", "accountnumber",
    "cardnumber", "cvv", "cvc", "plaintext", "ciphertext", "keymaterial", "iv", "nonce",
}

TOKEN_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{4,})?\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"(?i)\b(otp|pin)\s*[:=]?\s*\d{4,8}\b"), "[REDACTED_AUTH_VALUE]"),
]


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def redact_text(value: str) -> str:
    result = value
    for pattern, replacement in TOKEN_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact(value: Any, key: str | None = None) -> Any:
    """Recursively redact sensitive values before output or persistence."""
    if key and _normalized_key(key) in SENSITIVE_KEYS:
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


def permitted_runtime_evidence(event: dict[str, Any]) -> dict[str, Any]:
    """Keep only explicitly permitted runtime fields before persistence."""
    allowed = {
        "event", "algorithm", "crypto_bound", "enabled", "allowFileAccess",
        "allowContentAccess", "class", "method", "hook", "hook_status",
        "reason", "url_scheme", "transport",
    }
    return redact({key: value for key, value in event.items() if key in allowed})
