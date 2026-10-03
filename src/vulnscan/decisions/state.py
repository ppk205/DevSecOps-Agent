"""Redacted, bounded evidence envelopes for local decision backends."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from vulnscan.decisions.protocol import (
    INPUT_FORMAT_VERSION,
    MAX_INPUT_CHARS,
    REDACTED_KEYS,
)

MAX_STATE_TEXT_CHARS = MAX_INPUT_CHARS


_SECRET_KEYS = REDACTED_KEYS
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


def _state_text(
    state: Mapping[str, Any], max_chars: int = MAX_STATE_TEXT_CHARS
) -> tuple[str, bool]:
    text = json.dumps(
        _redact(dict(state)), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
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
    if max_chars < 2:
        raise ValueError("state limit must be at least two characters")
    redacted = _redact({k: v for k, v in state.items() if k not in {"finding_id", "run_id"}})
    # Bound the actual object sent to inference, keeping a valid JSON document.
    bounded: dict[str, Any] = {}
    truncated = False
    for key, value in sorted(redacted.items()):
        candidate = {**bounded, key: value}
        rendered = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(rendered) <= max_chars:
            bounded[key] = value
        elif isinstance(value, str):
            low, high = 0, len(value)
            while low < high:
                middle = (low + high + 1) // 2
                rendered = json.dumps(
                    {**bounded, key: value[:middle]},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                if len(rendered) <= max_chars:
                    low = middle
                else:
                    high = middle - 1
            if (
                len(
                    json.dumps(
                        {**bounded, key: value[:low]},
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                <= max_chars
            ):
                bounded[key] = value[:low]
            truncated = True
        else:
            truncated = True
    text, _ = _state_text(bounded, max_chars=max_chars)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {
        **bounded,
        "state_text": text,
        "state_hash": digest,
        "input_truncated": truncated,
        "input_format_version": INPUT_FORMAT_VERSION,
    }


def model_state(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """The exact hashed payload; never pass envelope bookkeeping to inference."""
    return {
        k: v
        for k, v in envelope.items()
        if k not in {"state_text", "state_hash", "input_truncated", "input_format_version"}
    }
