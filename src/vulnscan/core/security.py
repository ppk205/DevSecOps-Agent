"""Sanitize output at persistence and display boundaries."""

from __future__ import annotations

import os
import re
from typing import Any


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: "[REDACTED]"
            if k.lower()
            in {"secret", "match", "password", "api_key", "access_token", "authorization"}
            else sanitize(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        for key, secret in os.environ.items():
            if len(secret) >= 8 and any(
                s in key.upper() for s in ("TOKEN", "SECRET", "PASSWORD", "API_KEY")
            ):
                value = value.replace(secret, "[REDACTED]")
        value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
        value = re.sub(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
        value = re.sub(
            r"(?i)((?:password|api[_-]?key|token|secret)\s*[=:]\s*)[^\s,;]+", r"\1[REDACTED]", value
        )
        return value
    return value
