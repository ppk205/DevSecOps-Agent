"""Compare model-hunted vulns against deterministic scanner findings.

Pure function, no I/O. Match key: (normalized posix path, line ±3 lines
tolerance, CWE digits with a rule->CWE fallback map built at runtime from
``src/vulnscan/scanners/rules/*.yml`` ``metadata.cwe``).

Returns ``{"agreed": [...], "model_only": [...], "scanner_only": [...],
"counts": {...}}``. Report-only: matched items are cross-referenced, stored
findings are never merged or mutated.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_LINE_TOLERANCE = 3

# Directory holding the semgrep rule packs (java/javascript/python/php yml).
_RULES_DIR = Path(__file__).resolve().parent.parent / "scanners" / "rules"

# Parsed once on first use, then cached in module state.
_rule_cwe_cache: dict[str, str] | None = None

_CWE_DIGITS = re.compile(r"(\d+)")
_RULE_ID_LINE = re.compile(r"^\s*-\s*id\s*:\s*(\S+)\s*$")


def _scan_rules_text(text: str) -> dict[str, str]:
    """Extract ``{rule id: CWE digits}`` from one rules file's text.

    Each rule block declares ``- id: <rule-id>`` followed by a ``metadata:``
    section with a single-line ``cwe: ['CWE-NNN: ...']`` entry. The scan
    tracks the most recent rule id and records the first CWE entry seen
    under it — no YAML dependency required.
    """
    mapping: dict[str, str] = {}
    current_id = ""
    for line in text.splitlines():
        id_match = _RULE_ID_LINE.match(line)
        if id_match:
            current_id = id_match.group(1)
            continue
        if current_id and current_id not in mapping and "cwe" in line and "CWE" in line.upper():
            cwe_match = _CWE_DIGITS.search(line)
            if cwe_match:
                mapping[current_id] = cwe_match.group(1)
    return mapping


def _load_rule_cwe_map() -> dict[str, str]:
    """Build rule id -> CWE digits from every ``rules/*.yml`` file."""
    mapping: dict[str, str] = {}
    try:
        files = sorted(_RULES_DIR.glob("*.yml"))
    except OSError:
        return mapping
    for rules_file in files:
        try:
            text = rules_file.read_text(encoding="utf-8")
        except OSError:
            continue
        mapping.update(_scan_rules_text(text))
    return mapping


def rule_cwe_map() -> dict[str, str]:
    """Runtime rule->CWE map (parsed once, cached); ``{}`` when unavailable."""
    global _rule_cwe_cache
    if _rule_cwe_cache is None:
        _rule_cwe_cache = _load_rule_cwe_map()
    return _rule_cwe_cache


def _rule_cwe(rule_id: str) -> str:
    """CWE digits for a rule id of any language prefix; ``""`` when unknown."""
    return rule_cwe_map().get(rule_id, "")


def norm_path(path: str) -> str:
    """Normalize to a comparable posix path (strip ``./`` prefixes)."""
    text = str(path or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def cwe_digits(value: Any) -> str:
    """Extract CWE digits (``CWE-89`` -> ``89``); ``""`` when absent."""
    if value is None:
        return ""
    match = _CWE_DIGITS.search(str(value))
    return match.group(1) if match else ""


def _candidate_cwe(candidate: Any) -> str:
    if isinstance(candidate, dict):
        return cwe_digits(candidate.get("cwe"))
    return cwe_digits(getattr(candidate, "cwe", None))


def _candidate_location(candidate: Any) -> tuple[str, int]:
    if isinstance(candidate, dict):
        try:
            line = int(candidate.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        return norm_path(str(candidate.get("file", ""))), line
    line = getattr(candidate, "line", 0)
    try:
        line = int(line or 0)
    except (TypeError, ValueError):
        line = 0
    return norm_path(str(getattr(candidate, "file", ""))), line


def _finding_cwe(finding: Any) -> str:
    if isinstance(finding, dict):
        direct = cwe_digits(finding.get("cwe") or finding.get("cwe_category"))
        if direct:
            return direct
        return _rule_cwe(str(finding.get("rule_id", "")))
    cwe = cwe_digits(getattr(finding, "cwe_category", None))
    if cwe:
        return cwe
    for obs in getattr(finding, "observations", []) or []:
        cwe = cwe_digits(getattr(obs, "cwe_category", None))
        if cwe:
            return cwe
        rule_cwe = _rule_cwe(str(getattr(obs, "rule_id", "")))
        if rule_cwe:
            return rule_cwe
    return ""


def _finding_location(finding: Any) -> tuple[str, int]:
    if isinstance(finding, dict):
        try:
            line = int(finding.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        return norm_path(str(finding.get("file", ""))), line
    for obs in getattr(finding, "observations", []) or []:
        location = getattr(obs, "location", None)
        if location is None:
            continue
        try:
            line = int(getattr(location, "line_start", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        return norm_path(str(getattr(location, "file_path", ""))), line
    return "", 0


def compare_hunt_vs_scanners(candidates: list[Any], findings: list[Any]) -> dict[str, Any]:
    """Bucket hunted candidates vs scanner findings by (path, line±3, CWE).

    A candidate agrees with a finding when paths match exactly after
    normalization, lines are within ±3, and CWE digits agree — or either
    side carries no CWE information (then path+line alone decide). Each
    finding matches at most one candidate (first wins, input order kept).
    """
    agreed: list[dict[str, Any]] = []
    matched_findings: set[int] = set()
    matched_candidates: set[int] = set()

    finding_keys = [(_finding_location(f), _finding_cwe(f)) for f in findings]
    for ci, candidate in enumerate(candidates or []):
        (c_path, c_line), c_cwe = _candidate_location(candidate), _candidate_cwe(candidate)
        for fi, finding in enumerate(findings or []):
            if fi in matched_findings:
                continue
            (f_path, f_line), f_cwe = finding_keys[fi]
            if not c_path or c_path != f_path:
                continue
            if abs(c_line - f_line) > _LINE_TOLERANCE:
                continue
            if c_cwe and f_cwe and c_cwe != f_cwe:
                continue
            agreed.append({"candidate": candidate, "finding": finding})
            matched_findings.add(fi)
            matched_candidates.add(ci)
            break

    model_only = [c for i, c in enumerate(candidates or []) if i not in matched_candidates]
    scanner_only = [f for i, f in enumerate(findings or []) if i not in matched_findings]
    return {
        "agreed": agreed,
        "model_only": model_only,
        "scanner_only": scanner_only,
        "counts": {
            "agreed": len(agreed),
            "model_only": len(model_only),
            "scanner_only": len(scanner_only),
        },
    }
