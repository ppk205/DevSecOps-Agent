"""Redacted, bounded evidence envelopes for local decision backends."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

MAX_STATE_TEXT_CHARS = 1_500


_SECRET_KEYS = {"api_key", "apikey", "token", "password", "passwd", "secret", "authorization"}
_SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\b(?:sk|pk)-[A-Za-z0-9_-]{8,}"),
)


def _redact_text(value: str) -> str:
    redacted = value
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    redacted = re.sub(r"(?i)\bBearer\s+\[REDACTED\]", "Bearer [REDACTED]", redacted)
    return redacted


def _redact(value: Any, key: str | None = None) -> Any:
    if key and key.lower() in _SECRET_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


def _state_text(state: Mapping[str, Any], max_chars: int = MAX_STATE_TEXT_CHARS) -> tuple[str, bool]:
    text = json.dumps(_redact(dict(state)), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def build_evidence_state(
    state: Mapping[str, Any],
    *,
    max_chars: int = MAX_STATE_TEXT_CHARS,
) -> dict[str, Any]:
    """Redact, bound, and hash a state before passing it to Laya.

    The returned ``state_text`` is deterministic for cache keys and evidence
    artifacts; the original raw source is intentionally not retained here.
    """
    redacted = _redact(dict(state))
    text, truncated = _state_text(redacted, max_chars=max_chars)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {
        **redacted,
        "state_text": text,
        "state_hash": digest,
        "input_truncated": truncated,
    }
