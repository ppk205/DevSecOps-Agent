"""Credential loading from environment variables.

Keys are never returned to callers in a form suitable for embedding in
reports, logs, or model transcripts. The ``redact`` helper strips
credential-format values before any output leaves the provider boundary.
"""

from __future__ import annotations

import os
import re

# Format-specific patterns for real credential material. Deliberately narrow:
# bare words like "token", "key", or "secret" never trigger redaction, so
# code identifiers (``token.isEmpty()``), diff +/- lines, and JSON payloads
# pass through untouched.
_FORMAT_RES = (
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),  # OpenAI-style secret keys
    re.compile(r"ghp_[A-Za-z0-9]{8,}"),  # GitHub classic PAT
    re.compile(r"github_pat_[A-Za-z0-9_]{8,}"),  # GitHub fine-grained PAT
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ID
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{8,}"),  # Slack tokens
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),  # Bearer tokens
)

_SECRET_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET")
_MIN_SECRET_LEN = 8


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


def _secret_env_values() -> list[str]:
    """Literal values of secret-looking env vars, read at call time."""
    values = []
    for name, value in os.environ.items():
        if len(value) >= _MIN_SECRET_LEN and name.upper().endswith(_SECRET_SUFFIXES):
            values.append(value)
    return values


def redact(text: str) -> str:
    """Replace credential-format substrings in *text* with ``[REDACTED]``."""
    redacted = text
    for pattern in _FORMAT_RES:
        redacted = pattern.sub("[REDACTED]", redacted)
    for secret in _secret_env_values():
        if secret in redacted:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted
