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

#: Files whose average line length exceeds this are minified/vendored
#: bundles where every pattern co-occurs on one giant line (all FP).
#: Skipped with a recorded reason, same as oversized files.
MAX_AVG_LINE_LEN = 2000

#: Suffixes never meaningfully scanned (vendored minified bundles).
MINIFIED_SUFFIXES = (".min.js",)

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

_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:final\s+)?[A-Za-z_][\w<>\[\].,\s]*?\s+)?"
    r"(?P<var>[A-Za-z_]\w*)\s*(?<![=!<>])=\s*(?![=>])(?P<rhs>.+)$"
)

#: Method/function definitions captured for same-file call→param taint:
#: ``name`` + raw parameter list. Covers Java methods, Python defs,
#: JS functions/methods (best-effort, single-line signatures only).
_DEF_RE = re.compile(
    r"(?:def\s+|function\s+)?(?P<name>[A-Za-z_]\w*)\s*\((?P<params>.*)\)\s*(?:\{|:|throws\b)?\s*$"
)

#: A definition line carrying one of these marks user-controlled entry
#: data (framework annotations, servlet objects, explicit user-input
#: accessors). Only these taint all parameters — a bare word like
#: ``request`` alone is NOT enough (every framework handler takes one).
_ENTRY_MARK_RE = re.compile(
    r"@RequestParam|@RequestBody|@PathVariable|@RequestHeader|@CookieValue|"
    r"HttpServletRequest|HttpServletResponse|MultipartFile|"
    r"request\.(?:args|form|values|json|data|GET|POST|query|body|params)\b|"
    r"req\.(?:query|body|params)\b"
)

_CALL_RE = re.compile(r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^();]*)\)")

#: Append-assignment (``.=``/``+=``): keeps existing taint, adds RHS taint.
_APPEND_ASSIGN_RE = re.compile(
    r"(?<![\w=!<>])(?P<var>[A-Za-z_]\w*|\$\w+)\s*(?P<op>[+.]?=)\s*(?P<rhs>.+)$"
)

#: Heredoc start: ``$var .= <<<TAG`` or ``$var = <<<TAG``. Body lines up to
#: the lone ``TAG;`` terminator interpolate ``{$var}``/``$var``.
_HEREDOC_RE = re.compile(
    r"(?P<var>\$\w+)\s*(?P<op>\.?=)\s*<<<\s*(?P<tag>[A-Za-z_]\w*)"
)

#: Fallback for assignments buried in conditions/calls
#: (``while ((line = in.readLine()) != null)``). Used only when the
#: line-start assignment misses; same guards against ==/!=/=>.
_COND_ASSIGN_RE = re.compile(r"(?<![\w=!<>])(?P<var>[A-Za-z_]\w*)\s*=\s*(?![=>])(?P<rhs>[^;]+)")


def _split_params(raw: str) -> list[str]:
    """Last token of each comma part, annotations stripped."""
    out: list[str] = []
    for part in raw.split(","):
        part = re.sub(r"@\w+(?:\([^()]*\))?\s*", "", part).strip()
        tokens = re.findall(r"[A-Za-z_]\w*", part)
        if tokens:
            out.append(tokens[-1])
    return out


def _collect_defs(lines: list[str]) -> dict[str, list[str]]:
    """Method name -> parameter names, first definition wins."""
    defs: dict[str, list[str]] = {}
    for raw in lines:
        stripped = raw.strip()
        # Calls, control flow, and returns are not definitions.
        if stripped.startswith(("return", "if", "for", "while", "switch", "catch")):
            continue
        if not re.search(r"[{:]\s*$|throws\b", stripped):
            continue
        match = _DEF_RE.search(stripped)
        if match is None:
            continue
        name = match.group("name")
        if name in defs or name in {"if", "for", "while", "switch", "catch", "return"}:
            continue
        params = _split_params(match.group("params"))
        if params:
            defs[name] = params
    return defs


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
    # PHP-style ``$vars`` have no leading word boundary (``{`` → ``$`` are
    # both non-word chars), so anchor on "not preceded by a word char".
    if name.startswith("$"):
        return re.compile(r"(?<!\w)" + re.escape(name) + r"\b")
    return re.compile(r"\b" + re.escape(name) + r"\b")


def _line_sanitized(line: str, rule: Rule) -> bool:
    return any(
        rx.search(line) is not None for rx, prevent in rule.sanitizer_res if rule.attack in prevent
    )


def _scan_rule(
    name: str, lines: list[str], rule: Rule, defs: dict[str, list[str]] | None = None
) -> list[Finding]:
    tainted: dict[str, tuple[int, int]] = {}  # var -> (origin_line, hops)
    method_defs = defs if defs is not None else {}
    # Entry points: method parameters on definition lines carrying source
    # markers (Spring annotations, servlet request objects) start tainted.
    for lineno, raw in enumerate(lines, start=1):
        if _ENTRY_MARK_RE.search(raw) is None:
            continue
        match = _DEF_RE.search(raw.strip())
        if match is None:
            continue
        for param in _split_params(match.group("params")):
            if tainted.get(param) != (lineno, 0):
                tainted[param] = (lineno, 0)
    heredoc: tuple[str, str, bool] | None = None  # (var, tag, is_append), per pass
    for _ in range(MAX_ITERATIONS):
        changed = False
        heredoc = None
        for lineno, raw in enumerate(lines, start=1):
            # Heredoc bodies interpolate tainted vars into the heredoc var.
            if heredoc is not None:
                hvar, htag, _ = heredoc
                if raw.strip().rstrip(";") == htag:
                    heredoc = None
                    continue
                for tvar, (origin, hops) in list(tainted.items()):
                    if _word_rx(tvar).search(raw) is None:
                        continue
                    if hvar not in tainted or hops + 1 < tainted[hvar][1]:
                        tainted[hvar] = (origin, hops + 1)
                        changed = True
                    break
                continue
            hstart = _HEREDOC_RE.search(raw)
            if hstart is not None:
                hvar = hstart.group("var")
                if hstart.group("op") == "=" and hvar in tainted:
                    # Fresh heredoc assignment resets previous taint; the
                    # body lines below re-taint it if they interpolate
                    # tainted data. ``.=`` keeps accumulating instead.
                    del tainted[hvar]
                    changed = True
                heredoc = (hvar, hstart.group("tag"), hstart.group("op") == ".=")
            # Same-file call→param propagation runs on every line (calls
            # rarely look like assignments): foo(taintedArg) taints foo's
            # parameter at that position; the fixpoint loop carries it on.
            for call in _CALL_RE.finditer(raw):
                callee = call.group("name")
                if callee not in method_defs:
                    continue
                for arg, param in zip(
                    call.group("args").split(","), method_defs[callee]
                ):
                    for tvar, (origin, hops) in list(tainted.items()):
                        if _word_rx(tvar).search(arg) is None:
                            continue
                        if param not in tainted or hops + 1 < tainted[param][1]:
                            tainted[param] = (origin, hops + 1)
                            changed = True
                        break
            match = _ASSIGN_RE.match(raw)
            if match is None:
                match = _COND_ASSIGN_RE.search(raw)
            if match is None:
                # Append-assignment (``.=``/``+=``) never kills: it keeps
                # existing taint and adds RHS taint.
                appended = _APPEND_ASSIGN_RE.search(raw)
                if appended is not None:
                    var = appended.group("var")
                    rhs = appended.group("rhs")
                    if _line_sanitized(raw, rule):
                        if var in tainted:
                            del tainted[var]
                            changed = True
                        continue
                    for tvar, (origin, hops) in list(tainted.items()):
                        if _word_rx(tvar).search(rhs) is None:
                            continue
                        if var not in tainted or hops + 1 < tainted[var][1]:
                            tainted[var] = (origin, hops + 1)
                            changed = True
                        break
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
                if tvar == var or _word_rx(tvar).search(rhs) is None:
                    continue
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
    joined = [""] * len(lines)
    for i, raw in enumerate(lines):
        # Statement continuation window: multi-line calls keep the sink on
        # one line and tainted args on the next (builder-style chains).
        window = "\n".join(lines[i : i + 3])
        joined[i] = window
    for lineno, raw in enumerate(lines, start=1):
        window = joined[lineno - 1]
        sink_hit = any(rx.search(raw) is not None for rx in rule.sink_res)
        # The taint_sink pattern itself must sit on the reported line; the
        # 3-line window only helps find the tainted argument (prevents a
        # neighbor line's sink from claiming this line as its own).
        taint_hit = any(rx.search(raw) is not None for rx in rule.taint_sink_res)
        if not sink_hit and not taint_hit:
            continue
        if _line_sanitized(raw, rule):
            continue
        if sink_hit and any(rx.search(raw) is not None for rx in rule.source_res):
            confidence: Confidence = "High"
            source_line: int | None = lineno
        else:
            best_ref: tuple[int, int] | None = None
            for tvar, (origin, hops) in tainted.items():
                if _word_rx(tvar).search(window) is None:
                    continue
                if best_ref is None or hops < best_ref[1]:
                    best_ref = (origin, hops)
            if best_ref is None:
                # Search-mode rules fire Weak on pattern alone; taint-mode
                # rules (and taint_sinks) never fire without tainted data.
                if taint_hit and not sink_hit:
                    continue
                if not sink_hit or rule.mode == "taint":
                    continue
                confidence = "Weak"
                source_line = None
            else:
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
                message=rule.message,
                source_ref=rule.source_ref,
            )
        )
    return findings


_RESOURCE_CTOR_RE = re.compile(
    r"=\s*new\s+(FileInputStream|FileOutputStream|BufferedReader|BufferedWriter|"
    r"InputStreamReader|OutputStreamWriter|PrintWriter|PrintStream|Scanner|"
    r"Formatter|RandomAccessFile|FileChannel|Socket|ZipFile)\s*\("
)
_RESOURCE_CALL_RE = re.compile(
    r"=\s*(?:\w+\.)?(?:getConnection|createStatement|prepareStatement|openConnection)\s*\("
)
_RESOURCE_CLOSE_RE = re.compile(r"\.(?:close|disconnect|release)\s*\(")


def _scan_resources(name: str, lines: list[str], rule: Rule) -> list[Finding]:
    """Flag resource assignments never followed by `.close()` in-file.

    Best-effort OBL approximation: try-with-resources assignments
    (``try (Type var = ...)``) close implicitly and are skipped. Findings
    are Weak — cross-method closes are invisible to a file-local scan.
    """
    out: list[Finding] = []
    for lineno, raw in enumerate(lines, start=1):
        if "try (" in raw or "try(" in raw:
            continue
        opened = _RESOURCE_CTOR_RE.search(raw) or _RESOURCE_CALL_RE.search(raw)
        if opened is None:
            continue
        match = _ASSIGN_RE.match(raw) or _COND_ASSIGN_RE.search(raw)
        if match is None:
            continue
        var = match.group("var")
        if var in {"in", "out", "err"}:
            continue
        closed = any(
            _word_rx(var).search(later) is not None and _RESOURCE_CLOSE_RE.search(later) is not None
            for later in lines[lineno:]
        )
        if closed:
            continue
        out.append(
            Finding(
                rule_id=rule.id,
                cwe=rule.cwe,
                attack=rule.attack,
                severity=rule.severity,
                file=name,
                line=lineno,
                snippet=raw.strip()[:200],
                confidence="Weak",
                source_line=None,
                message=rule.message,
                source_ref=rule.source_ref,
            )
        )
    return out


def _scan_text(name: str, text: str, rules: Sequence[Rule]) -> list[Finding]:
    lines = text.splitlines()
    out: list[Finding] = []
    defs = _collect_defs(lines)
    for rule in rules:
        if rule.resource_check:
            out.extend(_scan_resources(name, lines, rule))
        else:
            out.extend(_scan_rule(name, lines, rule, defs))
    out.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return out


def _skip_reason(path: Path, text: str | None) -> str | None:
    """Why a file must not be pattern-scanned, or None to scan it."""
    if path.name.lower().endswith(MINIFIED_SUFFIXES):
        return "minified bundle: pattern scan skipped"
    if text is not None:
        lines = text.splitlines() or [""]
        if sum(len(line) for line in lines) / len(lines) > MAX_AVG_LINE_LEN:
            return "oversized lines (minified/vendored): pattern scan skipped"
    return None


def scan_file(path: str | Path, rules: Sequence[Rule]) -> list[Finding]:
    """Scan one file; missing/unreadable/oversized files yield no findings."""
    target = Path(path)
    try:
        if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
            return []
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if _skip_reason(target, text) is not None:
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
    oversized or unreadable files are recorded in ``skipped``. Only
    ``.git`` metadata and symlinks are skipped; other dot-directories
    (e.g. ``.mvn`` wrappers) are legitimate sources. A missing *root*
    yields an empty result.
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
        if any(part == ".git" for part in Path(rel).parts):
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
        reason = _skip_reason(child, text)
        if reason is not None:
            result.skipped.append(f"{rel} ({reason})")
            continue
        result.scanned.append(rel)
        result.findings.extend(_scan_text(rel, text, applicable))
    result.findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return result
