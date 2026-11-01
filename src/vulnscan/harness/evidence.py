"""Evidence checking for proposed findings.

The checker verifies that every citation the model wrote (file, line, code)
exists in the target, and that a CVSS v4.0 vector is valid. It never decides a
finding's status; a human does.
"""

from __future__ import annotations

from typing import Any

import cvss  # type: ignore[import-untyped]

from .workspace import Hop, PathEscape, Workspace

__all__ = ["check_citations", "score_cvss4"]

_CONTEXT = 2


def _collapse(text: str) -> str:
    return " ".join(text.split())


def check_citations(ws: Workspace, hops: list[Hop]) -> list[str]:
    """Report every citation that does not exist in the target."""
    if not hops:
        return ["no source-to-sink path cited"]
    errors: list[str] = []
    for hop in hops:
        try:
            path = ws.resolve(hop.file)
        except PathEscape:
            errors.append(f"{hop.file}:{hop.line}: file not in target")
            continue
        if not path.is_file():
            errors.append(f"{hop.file}:{hop.line}: file not in target")
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            errors.append(f"{hop.file}:{hop.line}: file not in target")
            continue
        if not 1 <= hop.line <= len(lines):
            errors.append(f"{hop.file}:{hop.line}: line out of range")
            continue
        window = lines[max(hop.line - 1 - _CONTEXT, 0) : hop.line + _CONTEXT]
        needle = _collapse(hop.code)
        if not needle or not any(needle in _collapse(text) for text in window):
            errors.append(f"{hop.file}:{hop.line}: code not found near line")
    return errors


def score_cvss4(vector: str) -> float:
    """Score a CVSS v4.0 vector; anything else raises ``ValueError``."""
    value = vector.strip()
    if not value.startswith("CVSS:4.0/"):
        raise ValueError(f"not a CVSS v4.0 vector: {vector!r}")
    try:
        scored: Any = cvss.CVSS4(value)
        return float(scored.base_score)
    except Exception as exc:
        raise ValueError(f"invalid CVSS v4.0 vector {vector!r}: {exc}") from exc
