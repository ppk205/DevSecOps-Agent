"""Credential separation for verification runs.

A verification subprocess must NEVER see provider credentials and must
NEVER inherit the host docker socket. This module produces the scrubbed
environment.
"""

from __future__ import annotations

import os
import re

# Patterns whose presence would leak provider credentials into a
# verification run. Matched case-insensitively against the env key.
_SENSITIVE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r".*_API_KEY$",
        r".*_API_SECRET$",
        r".*_TOKEN$",
        r".*_PASSWORD$",
        r".*_PASSWD$",
        r".*_SECRET$",
        r"^OPENAI.*$",
        r"^ANTHROPIC.*$",
        r"^AZURE.*KEY.*$",
        r"^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$",
        r"^GOOGLE.*KEY.*$",
        r"^GITHUB_TOKEN$",
        r"^GH_TOKEN$",
        r"^HF_TOKEN$",
        r"^OMNIROUTE.*KEY.*$",
        r"^OMNIROUTE.*TOKEN.*$",
    )
]


def _is_sensitive(key: str) -> bool:
    return any(p.search(key) for p in _SENSITIVE_PATTERNS)


def scrub_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Return an environment with provider credentials removed.

    If base is None, starts from os.environ (a copy, never mutated).
    """
    src = dict(base if base is not None else os.environ)
    scrubbed: dict[str, str] = {}
    removed: list[str] = []
    for k, v in src.items():
        if _is_sensitive(k):
            removed.append(k)
        else:
            scrubbed[k] = v
    scrubbed["_VULNSCAN_SCRUBBED_KEYS"] = ",".join(sorted(removed))
    return scrubbed


def assert_no_credentials(env: dict[str, str]) -> None:
    """Fail loudly if a credential still appears in the env."""
    leaked = [k for k in env if _is_sensitive(k) and k != "_VULNSCAN_SCRUBBED_KEYS"]
    if leaked:
        raise AssertionError(f"provider credentials present in env: {sorted(leaked)}")
