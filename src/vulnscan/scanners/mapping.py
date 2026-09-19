"""Shared exit-code interpretation and CWE mapping for scanner adapters."""

from __future__ import annotations

import re
from typing import Any

from vulnscan.contracts import CWECategory, Severity

# Exit codes common to CLI scanners.  Adapters must never treat an undocumented
# code as success; unknown codes are surfaced as errors with the raw stderr.
_SEMGREP_EXIT_CODES = {
    0: "no findings",
    1: "findings present (semgrep convention)",
    2: "semgrep ran with errors",
    7: "invalid rule schema",
    8: "missing required argument",
}

# --- native severity -> reference severity ----------------------------------

_NATIVE_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "blocker": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
}

# SpotBugs priorities -> reference severity (per SpotBugs docs).
_SPOTBUGS_PRIORITY: dict[str, Severity] = {
    "1": Severity.HIGH,
    "2": Severity.MEDIUM,
    "3": Severity.LOW,
}


def map_severity(native: str | None) -> Severity:
    """Map a native severity string onto the reference scale.

    Unknown values become :attr:`Severity.UNDETERMINED` rather than a guess.
    """
    if not native:
        return Severity.UNDETERMINED
    return _NATIVE_SEVERITY.get(native.strip().lower(), Severity.UNDETERMINED)


def map_spotbugs_priority(priority: str | int | None) -> Severity:
    """Map a SpotBugs priority (1/2/3) onto the reference severity scale."""
    key = str(priority).strip() if priority is not None else ""
    return _SPOTBUGS_PRIORITY.get(key, Severity.UNDETERMINED)


# --- CWE label parsing ------------------------------------------------------

_CWE_RE = re.compile(r"CWE[-\s]?(\d{1,6})", re.IGNORECASE)


def parse_cwe_labels(value: Any) -> list[str]:
    """Extract normalized ``CWE-<n>`` labels from a tool-supplied value.

    Accepts a string ("CWE-89, CWE-79"), a list of strings, or a list of dicts
    with ``id``/``cweId``/``name`` keys (NVD JSON style).  Returns a de-duplicated
    list in first-seen order; an empty list means the tool named no CWE.
    """
    if value is None:
        return []
    candidates: list[str] = []
    if isinstance(value, str):
        candidates.append(value)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, str):
                candidates.append(item)
            elif isinstance(item, dict):
                for k in ("id", "cweId", "cwe", "name", "label"):
                    if k in item and isinstance(item[k], str):
                        candidates.append(str(item[k]))
    elif isinstance(value, dict):
        for k in ("id", "cweId", "cwe", "name", "label"):
            if k in value and isinstance(value[k], str):
                candidates.append(str(value[k]))

    out: list[str] = []
    seen: set[str] = set()
    for cand in candidates:
        for m in _CWE_RE.finditer(cand):
            label = f"CWE-{int(m.group(1))}"
            if label not in seen:
                seen.add(label)
                out.append(label)
    return out


def cwe_category(label: str | None) -> CWECategory | None:
    """Return the matching :class:`CWECategory`, else ``None``.

    ``None`` (not ``UNCLASSIFIED``) means the tool's label could not be mapped;
    the normalizer decides whether to drop or downgrade the observation.
    """
    if not label:
        return None
    norm = label.strip().upper()
    norm = re.sub(r"\s+", "-", norm)
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}" if norm.isdigit() else norm
    for member in CWECategory:
        if member.value == norm:
            return member
    return None


def first_mapped_cwe(labels: list[str]) -> CWECategory | None:
    """First label that maps onto a known :class:`CWECategory`, else None."""
    for label in labels:
        cat = cwe_category(label)
        if cat is not None:
            return cat
    return None


def confidence_value(value: Any, default: float = 1.0) -> float:
    """Clamp a tool-reported confidence into [0.0, 1.0]."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, v))


def semgrep_exit_meaning(code: int) -> str:
    """Human-readable meaning of a semgrep exit code."""
    return _SEMGREP_EXIT_CODES.get(code, f"unknown exit code {code}")


__all__ = [
    "cwe_category",
    "confidence_value",
    "first_mapped_cwe",
    "map_severity",
    "map_spotbugs_priority",
    "parse_cwe_labels",
    "semgrep_exit_meaning",
]
