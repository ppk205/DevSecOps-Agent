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
"""

    {"id": "py-sqli", "cwe": "CWE-89", "attack": "sqli",
     "severity": "high",
     "sources": ["request\\\\.(args|form)"], "sinks": ["\\\\.execute\\\\s*\\\\("],
     "sanitizers": [{"pattern": "escape\\\\s*\\\\(", "prevent": ["xss"]}]}

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
    sanitizers: list[Sanitizer] = field(default_factory=list)
    source_res: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)
    sink_res: list[re.Pattern[str]] = field(init=False, repr=False, compare=False)
    sanitizer_res: list[tuple[re.Pattern[str], list[str]]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self.source_res = [_compile(p, self.id) for p in self.sources]
        self.sink_res = [_compile(p, self.id) for p in self.sinks]
        self.sanitizer_res = [(_compile(s.pattern, self.id), list(s.prevent)) for s in self.sanitizers]


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


def _parse_rule(item: Any, path: Path) -> Rule:
    if not isinstance(item, dict):
        raise ValueError(
            f"native_hunt: rule entry in {path} must be an object, got {type(item).__name__}"
        )
    rule_id = item.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError(f"native_hunt: rule entry in {path} is missing a string 'id'")
    cwe = item.get("cwe", "")
    attack = item.get("attack", "")
    severity = item.get("severity", "medium")
    for key, val in (("cwe", cwe), ("attack", attack), ("severity", severity)):
        if not isinstance(val, str):
            raise ValueError(f"native_hunt: {path} rule {rule_id!r} has non-string {key!r}")
    raw_sans = item.get("sanitizers", [])
    if not isinstance(raw_sans, list):
        raise ValueError(f"native_hunt: {path} rule {rule_id!r} 'sanitizers' must be a list")
    sanitizers = []
    for entry in raw_sans:
        if not isinstance(entry, dict) or not isinstance(entry.get("pattern"), str):
            raise ValueError(
                f"native_hunt: {path} rule {rule_id!r} sanitizer needs a string 'pattern'"
            )
        prevent = _str_list(entry.get("prevent", []), f"{rule_id!r} sanitizer 'prevent'", path)
        sanitizers.append(Sanitizer(pattern=entry["pattern"], prevent=prevent))
    return Rule(
        id=rule_id,
        cwe=cwe,
        attack=attack,
        severity=severity,
        sources=_str_list(item.get("sources"), f"{rule_id!r} 'sources'", path),
        sinks=_str_list(item.get("sinks"), f"{rule_id!r} 'sinks'", path),
        sanitizers=sanitizers,
    )


def load_rules(family: str) -> list[Rule]:
    """Load the rule pack for *family* (e.g. ``"python"``).

    Returns an empty list when no pack exists for the family; raises
    :class:`ValueError` when the pack file is present but malformed.
    Matching is case-insensitive.
    """
    path = RULES_DIR / f"{family.strip().lower()}.json"
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"native_hunt: invalid rule JSON in {path}: {exc}") from exc
    if not isinstance(raw, list):
        raise ValueError(f"native_hunt: rule pack {path} must hold a JSON list of rules")
    return [_parse_rule(item, path) for item in raw]
