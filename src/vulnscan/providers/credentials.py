"""Credential loading and redaction for outbound text.

Keys are never returned to callers in a form suitable for embedding in
reports, logs, or model transcripts. Redaction matches key *formats* and the
literal values of loaded key variables only, so real code identifiers such as
``token.isEmpty()`` survive both directions of the provider boundary.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

_KEY_RE = re.compile(r"(?:key|token|secret|password)", re.IGNORECASE)

# Ordered alternation: every match becomes [REDACTED]. Kept narrow on purpose;
# a broad "token" pattern corrupts Java source and JSON payloads.
_SECRET_RE = re.compile(
    r"\bsk-ant-[A-Za-z0-9_-]{20,}"
    r"|\b(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}"
    r"|\bghp_[A-Za-z0-9]{36}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{22,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|(?<=Bearer )[A-Za-z0-9._~+/-]{20,}=*"
)

# Variable names whose values are treated as secrets when loaded from the env.
_SECRET_ENV_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET")
_MIN_ENV_SECRET_LENGTH = 8

REDACTED = "[REDACTED]"


class CredentialError(Exception):
    """Raised when a required credential is missing or empty."""


def load_api_key(env_var: str) -> str:
    """Load an API key from the environment.

    Raises
    ------
    CredentialError
        If the variable is unset or empty after stripping whitespace.
    """
    value = os.environ.get(env_var, "").strip()
    if not value:
        raise CredentialError(
            f"Environment variable '{env_var}' is not set or empty. "
            f"Set it before running the provider."
        )
    return value


def _loaded_key_values() -> list[str]:
    """Literal values of secret-looking environment variables, longest first.

    Read at call time so a key loaded after import is still covered. Names and
    values never leave this function.
    """
    values = [
        value
        for name, value in os.environ.items()
        if name.endswith(_SECRET_ENV_SUFFIXES) and len(value) >= _MIN_ENV_SECRET_LENGTH
    ]
    return sorted(set(values), key=len, reverse=True)


def redact(text: str) -> str:
    """Replace key-shaped substrings and loaded key values with ``[REDACTED]``."""
    redacted = _SECRET_RE.sub(REDACTED, text)
    for value in _loaded_key_values():
        if value in redacted:
            redacted = redacted.replace(value, REDACTED)
    return redacted


def redact_value(value: Any) -> Any:
    """Deep-copy *value*, redacting every string. Keys and scalars are kept."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value


def redact_json(value: Any, *, indent: int | None = None) -> str:
    """Serialize *value* as JSON after redacting its strings.

    Serializing through ``default=str`` first means objects that only become
    strings during serialization are redacted too, and the output is always
    valid JSON because redaction never runs over the serialized text.
    """
    return json.dumps(redact_value(json.loads(json.dumps(value, default=str))), indent=indent)
