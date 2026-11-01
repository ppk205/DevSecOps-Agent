"""Shared, jailed source-excerpt readers for AI stages.

Both the per-finding review loop and the hunt-pipeline Laya verification
need the same thing: a bounded, numbered window of source around a
location, resolved inside the immutable scan snapshot. Centralized here so
the behavior (jail, radius, truncation) stays identical everywhere.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

_EXCERPT_CHARS = 3000


def _resolve_inside(root: Path, rel: str) -> Path | None:
    """Resolve *rel* inside *root*; None when it escapes the snapshot."""
    try:
        target = (root / rel).resolve()
    except (OSError, ValueError):
        return None
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None
    return target


def code_excerpt(snapshot_root: str | Path, file_path: str, line: int, radius: int = 30) -> str:
    """Read ±radius numbered lines around *line* in *file_path* (jailed)."""
    target = _resolve_inside(Path(snapshot_root), file_path)
    if target is None or not target.is_file():
        return "(no source excerpt available)"
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(no source excerpt available)"
    if not lines:
        return "(no source excerpt available)"
    try:
        anchor = int(line)
    except (TypeError, ValueError):
        anchor = 1
    start = max(1, anchor - radius)
    end = min(len(lines), anchor + radius)
    numbered = [f"{n}: {lines[n - 1]}" for n in range(start, end + 1)]
    return f"--- {file_path} (lines {start}-{end}) ---\n" + "\n".join(numbered)[:_EXCERPT_CHARS]


def code_excerpt_for_finding(snapshot_root: str, finding: Any, radius: int = 30) -> str:
    """Read ±radius lines around the first observation location (jailed)."""
    for obs in finding.observations:
        if obs.location is None:
            continue
        excerpt = code_excerpt(
            snapshot_root, obs.location.file_path, obs.location.line_start, radius
        )
        if excerpt != "(no source excerpt available)":
            return excerpt
    return "(no source excerpt available)"
