"""Rule model and loader for the native taint-hunt engine.

Two pack shapes are accepted (both live in ``rules/<family>.json``):

* Taint shape — a JSON list of objects with ``sources``, ``sinks`` and
  ``sanitizers`` (``[{"id": ..., "cwe": ..., "attack": ..., "severity":
  ..., "sources": [<regex>], "sinks": [<regex>], "sanitizers":
  [{"pattern": <regex>, "prevent": [<attack>, ...]}]}]``). The engine
  tracks ``sources`` through assignments into ``sinks``.
* Port shape — ``{"language": ..., "rules": [...]}`` where each rule
  carries sink ``patterns`` (ports of the Semgrep YAML packs). These get
  the family's default source/sanitizer sets below, so they participate
  in taint flow; a rule with no source model still reports sink matches
  as ``Weak`` findings.

``attack`` names the capability a finding reports; a sanitizer only
cleanses lines for the attacks listed in its ``prevent`` set, so an XSS
escaper never silences a SQL-injection rule.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RULES_DIR = Path(__file__).resolve().parent / "rules"

#: Default source regexes applied to ported (sink-only) rules per family.
_FAMILY_SOURCES: dict[str, list[str]] = {
    "python": [r"request\.(args|form|values|json|data|GET|POST)", r"\binput\s*\("],
    "javascript": [r"req\.(query|body|params)", r"location\.(search|hash)", r"document\.URL"],
    "java": [r"request\.getParameter", r"getParameter\s*\("],
    "php": [r"\$_(GET|POST|REQUEST|COOKIE)"],
    "generic": [r"\brequest\b", r"\binput\s*\(", r"\bargv\b"],
}

#: Default sanitizers (pattern, prevented attacks) for ported rules.
_FAMILY_SANITIZERS: dict[tuple[str, str], list[tuple[str, list[str]]]] = {
    ("python", "xss"): [(r"escape\s*\(", ["xss"])],
    ("python", "command_injection"): [(r"shlex\.quote\s*\(", ["command_injection"])],
    ("javascript", "xss"): [(r"encodeURIComponent\s*\(|DOMPurify\.sanitize\s*\(", ["xss"])],
    ("java", "xss"): [(r"escapeHtml|StringEscapeUtils", ["xss"])],
    ("php", "xss"): [(r"htmlspecialchars\s*\(", ["xss"])],
    ("php", "command_injection"): [(r"escapeshellarg\s*\(", ["command_injection"])],
}


@dataclass
class Sanitizer:
    """One cleansing pattern; only kills flow for the listed attacks."""

    pattern: str
    prevent: list[str] = field(default_factory=list)


@dataclass
class Rule:
    """One taint rule with precompiled regexes (compiled in post-init)."""

    id: str
    cwe: str = ""
    attack: str = ""
    severity: str = "medium"
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    taint_sinks: list[str] = field(default_factory=list)
    sanitizers: list[Sanitizer] = field(default_factory=list)
    message: str = ""
    source_ref: str = ""
    source_res: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)
    sink_res: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)
    taint_sink_res: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)
    sanitizer_res: list[tuple[re.Pattern[str], list[str]]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self.source_res = [_compile(p, self.id) for p in self.sources]
        self.sink_res = [_compile(p, self.id) for p in self.sinks]
        self.taint_sink_res = [_compile(p, self.id) for p in self.taint_sinks]
        self.sanitizer_res = [
            (_compile(s.pattern, self.id), list(s.prevent)) for s in self.sanitizers
        ]


def _compile(pattern: str, rule_id: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"native_hunt: rule {rule_id!r}: bad regex {pattern!r}: {exc}") from exc


def _str_list(value: Any, what: str, path: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"native_hunt: {path} rule {what} must be a list of strings")
    return list(value)


def _opt_str(value: Any, what: str, path: Path) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    raise ValueError(
        f"native_hunt: {path} rule field {what} must be a string, got {type(value).__name__}"
    )


def _parse_rule(item: Any, path: Path, family: str, ported: bool) -> Rule:
    if not isinstance(item, dict):
        raise TypeError(
            f"native_hunt: rule entry in {path} must be an object, got {type(item).__name__}"
        )
    rule_id = item.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError(f"native_hunt: rule entry in {path} is missing a string 'id'")
    sinks = _str_list(item.get("sinks"), f"{rule_id!r} 'sinks'", path)
    if not sinks:
        sinks = _str_list(item.get("patterns"), f"{rule_id!r} 'patterns'", path)
    if not sinks:
        raise ValueError(f"native_hunt: {path} rule {rule_id!r} has no 'sinks' (or 'patterns')")
    if "sources" in item:
        sources = _str_list(item.get("sources"), f"{rule_id!r} 'sources'", path)
    elif ported:
        sources = list(_FAMILY_SOURCES.get(family, _FAMILY_SOURCES["generic"]))
    else:
        sources = []
    attack = _opt_str(item.get("attack", ""), f"{rule_id!r} 'attack'", path)
    if "sanitizers" in item:
        raw_sans = item.get("sanitizers")
        if not isinstance(raw_sans, list):
            raise ValueError(f"native_hunt: {path} rule {rule_id!r} 'sanitizers' must be a list")
        sanitizers = []
        for entry in raw_sans:
            if not isinstance(entry, dict) or not isinstance(entry.get("pattern"), str):
                raise TypeError(
                    f"native_hunt: {path} rule {rule_id!r} sanitizer needs a string 'pattern'"
                )
            prevent = _str_list(entry.get("prevent", []), f"{rule_id!r} sanitizer 'prevent'", path)
            sanitizers.append(Sanitizer(pattern=entry["pattern"], prevent=prevent))
    elif ported:
        sanitizers = [
            Sanitizer(pattern=pat, prevent=list(prev))
            for pat, prev in _FAMILY_SANITIZERS.get((family, attack), [])
        ]
    else:
        sanitizers = []
    return Rule(
        id=rule_id,
        cwe=_opt_str(item.get("cwe", ""), f"{rule_id!r} 'cwe'", path),
        attack=attack,
        severity=_opt_str(item.get("severity", "medium"), f"{rule_id!r} 'severity'", path),
        sources=sources,
        sinks=sinks,
        taint_sinks=_str_list(item.get("taint_sinks"), f"{rule_id!r} 'taint_sinks'", path),
        sanitizers=sanitizers,
        message=_opt_str(item.get("message", ""), f"{rule_id!r} 'message'", path),
        source_ref=_opt_str(item.get("source", ""), f"{rule_id!r} 'source'", path),
    )


def load_rules(family: str) -> list[Rule]:
    """Load the rule pack for *family* (e.g. ``"python"``).

    Accepts the taint shape (JSON list) and the ported shape
    (``{"language": ..., "rules": [...]}`` with sink ``patterns``).
    Returns an empty list when no pack exists; raises :class:`ValueError`
    when the pack file is present but malformed. Case-insensitive.
    """
    name = family.strip().lower()
    path = RULES_DIR / f"{name}.json"
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"native_hunt: invalid rule JSON in {path}: {exc}") from exc
    if isinstance(raw, list):
        return [_parse_rule(item, path, name, ported=False) for item in raw]
    if isinstance(raw, dict) and isinstance(raw.get("rules"), list):
        return [_parse_rule(item, path, name, ported=True) for item in raw["rules"]]
    raise ValueError(f"native_hunt: rule pack {path} must hold a JSON list or a 'rules' object")
