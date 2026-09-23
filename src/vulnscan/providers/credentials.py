"""Credential loading from environment variables.

Keys are never returned to callers in a form suitable for embedding in
reports, logs, or model transcripts. The ``redact`` helper strips all
key-like values before any output leaves the provider boundary.
"""

from __future__ import annotations

import os
import re

_KEY_RE = re.compile(r"(?:key|token|secret|password)", re.IGNORECASE)


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


def redact(text: str) -> str:
    """Replace API-key-like substrings in *text* with ``[REDACTED]``."""
    # Match lines like  Authorization: Bearer sk-xxx  or  api_key=xxx
    return re.sub(
        r"(?:sk|pk|tok|api)[_-]?[A-Za-z0-9\-_.]{8,}",
        "[REDACTED]",
        text,
    )
