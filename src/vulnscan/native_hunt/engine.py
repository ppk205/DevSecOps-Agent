"""Three-iteration regex taint engine over one file or a snapshot tree.

Semantics (deliberately small and documented):

* Sources taint simple ``name = <expr>`` assignments when the line matches
  a rule's source regex. Only bare names are tracked (no attributes,
  tuples, or augmented assignment) — anything fancier is out of scope for
  a line-oriented engine.
* Taint propagates when an assignment's right-hand side references a
  tainted variable, up to :data:`MAX_ITERATIONS` fixpoint passes so chains
  like ``a -> b -> c -> sink`` resolve regardless of line order.
  Reassigning a variable to untainted data kills its taint.
* A line matching a sanitizer whose ``prevent`` list holds the rule's
  attack kills the assigned variable's taint, and a sink on such a line
  never fires. Sanitizers for other attacks are ignored.
* Confidence: ``High`` when the sink line itself contains the source (or
  uses a variable assigned directly from a source, 0 hops), ``Medium``
  for one hop, ``Weak`` for two or more, or for sink matches of rules
  with no source model (sink-only ports carry no provenance).
* Missing, unreadable, or oversized files yield no findings instead of
  raising; :func:`scan_snapshot` records oversized/unreadable files in
  ``SnapshotResult.skipped``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Literal

from .taint import RULES_DIR, Rule, load_rules

#: Files larger than this are skipped (bounded runtime on generated bundles).
MAX_FILE_BYTES = 256 * 1024

#: Fixpoint passes for taint propagation.
MAX_ITERATIONS = 3

#: Suffix map used by scan_snapshot; packs for other families apply to every file.
FAMILY_EXTENSIONS: dict[str, frozenset[str]] = {
    "python": frozenset({".py"}),
    "javascript": frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"}),
    "java": frozenset({".java", ".jsp", ".jspx"}),
    "php": frozenset({".php", ".phtml"}),
}

Confidence = Literal["High", "Medium", "Weak"]

_ASSIGN_RE = re.compile(r"^\s*(?P<var>[A-Za-z_]\w*)\s*(?<![=!<>])=\s*(?![=>])(?P<rhs>.+)$")


@dataclass
class Finding:
    """One tainted-data-reaches-sink observation."""

    rule_id: str
    cwe: str
    attack: str
    severity: str
    file: str
    line: int
    snippet: str
    confidence: Confidence
    source_line: int | None = None
    message: str = ""
    source_ref: str = ""


@dataclass
class SnapshotResult:
    """Outcome of scanning a snapshot tree."""

    findings: list[Finding] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


@lru_cache(maxsize=4096)
def _word_rx(name: str) -> re.Pattern[str]:
    return re.compile(r"\b" + re.escape(name) + r"\b")


def _line_sanitized(line: str, rule: Rule) -> bool:
    return any(rx.search(line) is not None for rx, prevent in rule.sanitizer_res if rule.attack in prevent)


def _scan_rule(name: str, lines: list[str], rule: Rule) -> list[Finding]:
    tainted: dict[str, tuple[int, int]] = {}  # var -> (origin_line, hops)
    for _ in range(MAX_ITERATIONS):
        changed = False
        for lineno, raw in enumerate(lines, start=1):
            match = _ASSIGN_RE.match(raw)
            if match is None:
                continue
            var, rhs = match.group("var"), match.group("rhs")
            if _line_sanitized(raw, rule):
                if var in tainted:
                    del tainted[var]
                    changed = True
                continue
            if any(rx.search(raw) is not None for rx in rule.source_res):
                if tainted.get(var) != (lineno, 0):
                    tainted[var] = (lineno, 0)
                    changed = True
                continue
            best: tuple[int, int] | None = None
            for tvar, (origin, hops) in tainted.items():
                if tvar != var and _word_rx(tvar).search(rhs) is not None:
                    if best is None or hops < best[1]:
                        best = (origin, hops)
            if best is not None:
                if var not in tainted or best[1] + 1 < tainted[var][1]:
                    tainted[var] = (best[0], best[1] + 1)
                    changed = True
            elif var in tainted:
                del tainted[var]  # reassigned to untainted data
                changed = True
        if not changed:
            break

    findings: list[Finding] = []
    for lineno, raw in enumerate(lines, start=1):
        if not any(rx.search(raw) is not None for rx in rule.sink_res):
            continue
        if _line_sanitized(raw, rule):
            continue
        if any(rx.search(raw) is not None for rx in rule.source_res):
            confidence: Confidence = "High"
            source_line: int | None = lineno
        else:
            best_ref: tuple[int, int] | None = None
            for tvar, (origin, hops) in tainted.items():
                if _word_rx(tvar).search(raw) is not None:
                    if best_ref is None or hops < best_ref[1]:
                        best_ref = (origin, hops)
            if best_ref is None:
                continue
            source_line = best_ref[0]
            confidence = "High" if best_ref[1] == 0 else "Medium" if best_ref[1] == 1 else "Weak"
        findings.append(
            Finding(
                rule_id=rule.id,
                cwe=rule.cwe,
                attack=rule.attack,
                severity=rule.severity,
                file=name,
                line=lineno,
                snippet=raw.strip()[:200],
                confidence=confidence,
                source_line=source_line,
            )
        )
    return findings


def _scan_text(name: str, text: str, rules: Sequence[Rule]) -> list[Finding]:
    lines = text.splitlines()
    out: list[Finding] = []
    for rule in rules:
        out.extend(_scan_rule(name, lines, rule))
    out.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return out


def scan_file(path: str | Path, rules: Sequence[Rule]) -> list[Finding]:
    """Scan one file; missing/unreadable/oversized files yield no findings."""
    target = Path(path)
    try:
        if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
            return []
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return _scan_text(str(target), text, rules)


def _family_for_suffix(suffix: str) -> str | None:
    for family, exts in FAMILY_EXTENSIONS.items():
        if suffix in exts:
            return family
    return None


def scan_snapshot(root: str | Path, families: Sequence[str] | None = None) -> SnapshotResult:
    """Scan every file under *root* matching *families* (defaults to all packs).

    Files whose suffix matches no requested known family are ignored;
    oversized or unreadable files are recorded in ``skipped``. Hidden
    paths (any part starting with ``.``) and symlinks are skipped. A
    missing *root* yields an empty result.
    """
    result = SnapshotResult()
    root_path = Path(root)
    if not root_path.is_dir():
        return result
    wanted = [f.strip().lower() for f in (families if families is not None else [])]
    if not wanted:
        wanted = sorted(p.stem for p in RULES_DIR.glob("*.json"))
    packs = [(fam, load_rules(fam)) for fam in wanted]
    packs = [(fam, rules) for fam, rules in packs if rules]
    if not packs:
        return result
    for child in sorted(root_path.rglob("*")):
        if child.is_symlink() or not child.is_file():
            continue
        try:
            rel = child.relative_to(root_path).as_posix()
        except ValueError:
            continue
        if any(part.startswith(".") for part in Path(rel).parts):
            continue
        suffix_family = _family_for_suffix(child.suffix.lower())
        applicable: list[Rule] = []
        for pack_family, rules in packs:
            if pack_family in FAMILY_EXTENSIONS and suffix_family != pack_family:
                continue
            applicable.extend(rules)
        if not applicable:
            continue
        try:
            if child.stat().st_size > MAX_FILE_BYTES:
                result.skipped.append(rel)
                continue
            text = child.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result.skipped.append(rel)
            continue
        result.scanned.append(rel)
        result.findings.extend(_scan_text(rel, text, applicable))
    result.findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return result
