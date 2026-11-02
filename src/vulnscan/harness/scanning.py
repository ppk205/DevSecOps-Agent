"""Harness scan tools: file inventory, candidate extraction, route lookup.

Detection is hand-written source–sink matching over the target checkout. No
third-party scanner runs here; those are baselines only. Every hit is a
*candidate* for the model to investigate, never a confirmed vulnerability.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from vulnscan.context.source_index import SourceIndex, build_source_index

from .workspace import Candidate, Workspace

__all__ = [
    "ROLE_CHECK",
    "SINK_RULES",
    "SinkRule",
    "extract_candidates",
    "inventory",
    "lookup_route",
]

ROLE_CHECK = re.compile(
    r'getAttribute\(\s*"role"\s*\)|isUserInRole\(|hasRole\(|requireRole\(|requireAdmin\('
)
SOURCE_READ = re.compile(
    r"getParameter\(|getHeader\(|getCookies\(|getInputStream\(|getReader\("
    r"|getQueryString\(|getPathInfo\("
)
_PROTECTED_PATH = re.compile(r"^/(api/)?(admin|seller|shipper)\b")
_WEB_SERVLET = "@WebServlet"
_LITERAL_ARGUMENT = re.compile(r'\s*"[^"]*"\s*[,)]')

_KIND_BY_SUFFIX = {".java": "java", ".jsp": "jsp", ".xml": "xml"}


@dataclass(frozen=True)
class SinkRule:
    """One line-level source–sink pattern family."""

    kind: str
    cwe: str
    suffixes: tuple[str, ...]
    patterns: tuple[re.Pattern[str], ...]
    needs_nonliteral: bool = False
    file_requires: re.Pattern[str] | None = None
    file_excludes: re.Pattern[str] | None = None


SINK_RULES: tuple[SinkRule, ...] = (
    SinkRule(
        kind="sql_concat",
        cwe="CWE-89",
        suffixes=(".java",),
        patterns=(
            re.compile(
                r"(executeQuery|executeUpdate|execute|prepareStatement|prepareCall|addBatch)"
                r'\s*\(.*("\s*\+|\+\s*")'
            ),
            re.compile(r'(?i)"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+\s*[A-Za-z_]'),
        ),
    ),
    SinkRule(
        kind="command",
        cwe="CWE-78",
        suffixes=(".java",),
        patterns=(re.compile(r"Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\("),),
    ),
    SinkRule(
        kind="servlet_xss",
        cwe="CWE-79",
        suffixes=(".java",),
        patterns=(re.compile(r"(\.getWriter\(\)|\bout)\.(print|println|write)\("),),
        needs_nonliteral=True,
    ),
    SinkRule(
        kind="jsp_xss",
        cwe="CWE-79",
        suffixes=(".jsp",),
        patterns=(re.compile(r"<%=(?![^%]*(escape|encode))|\$\{\s*param\."),),
    ),
    SinkRule(
        kind="path",
        cwe="CWE-22",
        suffixes=(".java",),
        patterns=(
            re.compile(r"new\s+(File|FileInputStream|FileOutputStream|FileReader)\(|Paths\.get\("),
        ),
        needs_nonliteral=True,
    ),
    SinkRule(
        kind="redirect",
        cwe="CWE-601",
        suffixes=(".java",),
        patterns=(re.compile(r"sendRedirect\("),),
        needs_nonliteral=True,
    ),
    SinkRule(
        kind="ssrf",
        cwe="CWE-918",
        suffixes=(".java",),
        patterns=(re.compile(r"new\s+URL\("),),
        needs_nonliteral=True,
    ),
    SinkRule(
        kind="xxe",
        cwe="CWE-611",
        suffixes=(".java",),
        patterns=(
            re.compile(
                r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)"
                r"\.newInstance\("
            ),
        ),
        file_excludes=re.compile(r"setFeature\("),
    ),
    SinkRule(
        kind="deserialize",
        cwe="CWE-502",
        suffixes=(".java",),
        patterns=(re.compile(r"new\s+ObjectInputStream\(|\.readObject\("),),
    ),
    SinkRule(
        kind="weak_crypto",
        cwe="CWE-327",
        suffixes=(".java",),
        patterns=(
            re.compile(
                r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"'
                r'|Cipher\.getInstance\(\s*"[^"]*(DES|ECB|RC4)'
            ),
        ),
    ),
    SinkRule(
        kind="weak_random",
        cwe="CWE-330",
        suffixes=(".java",),
        patterns=(re.compile(r"new\s+(java\.util\.)?Random\(|Math\.random\("),),
    ),
    SinkRule(
        kind="hardcoded_secret",
        cwe="CWE-798",
        suffixes=(".java", ".properties", ".xml"),
        patterns=(
            re.compile(r'(?i)"[^"]*(secret|passw|api[_-]?key|token)[^"]*"\s*\.equals\('),
            re.compile(
                r'(?i)\b\w*(secret|password|passwd|apikey|api_key|token)\w*\s*=\s*"[^"]{6,}"'
            ),
        ),
    ),
    SinkRule(
        kind="debug_disclosure",
        cwe="CWE-200",
        suffixes=(".java",),
        patterns=(re.compile(r'(?i)\b(write|print|println|put|append)\(.*"[^"]*debug\w*'),),
    ),
    SinkRule(
        kind="public_admin_path",
        cwe="CWE-306",
        suffixes=(".java",),
        patterns=(re.compile(r'"/(api/)?admin[^"]*"'),),
        file_requires=re.compile(r"implements\s+Filter|@WebFilter"),
    ),
)


def _kind(path: Path) -> str:
    return _KIND_BY_SUFFIX.get(path.suffix.lower(), "other")


def _files(ws: Workspace, globs: list[str] | None = None) -> list[Path]:
    return ws.files(globs)


def _source_index(ws: Workspace) -> SourceIndex:
    paths = [
        ws.resolve(path.relative_to(ws.target.resolve()).as_posix())
        for path in _files(ws, ["**/*.java", "**/web.xml"])
    ]
    return build_source_index(ws.target, files=paths)


def inventory(ws: Workspace, globs: list[str]) -> list[dict[str, object]]:
    """List files in scope with kind, line count and content hash."""
    entries: list[dict[str, object]] = []
    for path in _files(ws, globs):
        relative = path.relative_to(ws.target.resolve()).as_posix()
        try:
            data = ws.resolve(relative).read_bytes()
        except OSError:
            continue
        entries.append(
            {
                "path": relative,
                "kind": _kind(path),
                "lines": data.count(b"\n") + (0 if data.endswith(b"\n") else 1),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return entries


def _is_literal_call(line: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    """True when the first argument of the matched call is one string literal."""
    for pattern in patterns:
        match = pattern.search(line)
        if match is None:
            continue
        # Every non-literal rule pattern ends at the call's opening parenthesis,
        # so the text after the match is the first argument.
        return _LITERAL_ARGUMENT.match(line[match.end() :]) is not None
    return False


def _snippet(lines: list[str], line: int) -> str:
    first = max(line - 2, 1)
    last = min(line + 2, len(lines))
    return "\n".join(lines[first - 1 : last])


def _candidate_id(relative: str, line: int, kind: str) -> str:
    return hashlib.sha256(f"{relative}:{line}:{kind}".encode()).hexdigest()[:12]


def _servlet_for(
    index: SourceIndex, files_by_stem: dict[str, str]
) -> list[tuple[str, str, str, int]]:
    """(class, url_pattern, file, @WebServlet line) for protected routes."""
    routes: list[tuple[str, str, str, int]] = []
    for servlet in index.servlets:
        if not _PROTECTED_PATH.search(servlet.url_pattern):
            continue
        stem = servlet.class_name.rsplit(".", 1)[-1]
        relative = files_by_stem.get(stem)
        if relative is None:
            continue
        routes.append((servlet.class_name, servlet.url_pattern, relative, 0))
    return routes


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    return 1


def extract_candidates(
    ws: Workspace,
    classes: list[str] | None = None,
    paths: list[str] | None = None,
) -> list[Candidate]:
    """Extract source–sink candidates from the target and record them."""
    root = ws.target.resolve()
    texts: dict[str, str] = {}
    index = _source_index(ws)
    servlet_by_stem = {servlet.class_name.rsplit(".", 1)[-1]: servlet for servlet in index.servlets}
    files_by_stem: dict[str, str] = {}
    for path in _files(ws, ["**/*.java"]):
        relative = path.relative_to(root).as_posix()
        files_by_stem.setdefault(path.stem, relative)

    selected = [
        path
        for path in _files(ws, paths)
        if path.suffix.lower() in {".java", ".jsp", ".properties", ".xml"}
    ]
    selected_relatives = {path.relative_to(root).as_posix() for path in selected}
    wanted = {cwe.upper() for cwe in classes} if classes else None
    found: dict[tuple[str, int, str], Candidate] = {}

    for path in selected:
        relative = path.relative_to(root).as_posix()
        try:
            text = ws.resolve(relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        texts[relative] = text
        lines = text.splitlines()
        has_source = SOURCE_READ.search(text) is not None
        has_auth_check = ROLE_CHECK.search(text) is not None
        servlet = servlet_by_stem.get(path.stem)
        route = servlet.url_pattern if servlet is not None else None
        for rule in SINK_RULES:
            if path.suffix.lower() not in rule.suffixes:
                continue
            if wanted is not None and rule.cwe not in wanted:
                continue
            if rule.file_requires is not None and not rule.file_requires.search(text):
                continue
            if rule.file_excludes is not None and rule.file_excludes.search(text):
                continue
            for number, line in enumerate(lines, start=1):
                if not any(pattern.search(line) for pattern in rule.patterns):
                    continue
                if rule.needs_nonliteral and _is_literal_call(line, rule.patterns):
                    continue
                key = (relative, number, rule.kind)
                if key in found:
                    continue
                found[key] = Candidate(
                    id=_candidate_id(relative, number, rule.kind),
                    cwe=rule.cwe,
                    kind=rule.kind,
                    file=relative,
                    line=number,
                    snippet=_snippet(lines, number),
                    route=route,
                    has_source=has_source,
                    has_auth_check=has_auth_check,
                )

    for class_name, url_pattern, relative, _ in _servlet_for(index, files_by_stem):
        if relative not in selected_relatives:
            continue
        if wanted is not None and "CWE-862" not in wanted:
            continue
        servlet_text = texts.get(relative)
        if servlet_text is None:
            try:
                servlet_text = ws.resolve(relative).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            texts[relative] = servlet_text
        if ROLE_CHECK.search(servlet_text):
            continue
        servlet_line = _line_of(servlet_text, _WEB_SERVLET)
        key = (relative, servlet_line, "missing_role_check")
        if key in found:
            continue
        servlet_lines = servlet_text.splitlines()
        found[key] = Candidate(
            id=_candidate_id(relative, servlet_line, "missing_role_check"),
            cwe="CWE-862",
            kind="missing_role_check",
            file=relative,
            line=servlet_line,
            snippet=_snippet(servlet_lines, servlet_line),
            route=url_pattern,
            has_source=SOURCE_READ.search(servlet_text) is not None,
            has_auth_check=False,
        )

    candidates = [found[key] for key in sorted(found)]
    for candidate in candidates:
        ws.candidates[candidate.id] = candidate
    return candidates


def lookup_route(ws: Workspace, query: str) -> dict[str, object]:
    """Servlet route, filters and auth checks for a class name or URL."""
    root = ws.target.resolve()
    index = _source_index(ws)
    files_by_stem: dict[str, str] = {}
    for path in _files(ws, ["**/*.java"]):
        files_by_stem.setdefault(path.stem, path.relative_to(root).as_posix())

    servlets: list[dict[str, object]] = []
    for servlet in index.servlets:
        stem = servlet.class_name.rsplit(".", 1)[-1]
        relative = files_by_stem.get(stem) or ""
        matches = query in {servlet.class_name, stem, servlet.url_pattern}
        if query.startswith("/"):
            matches = matches or _url_matches(servlet.url_pattern, query, default=True)
        if not matches and relative:
            matches = relative == query or relative.endswith(f"/{query}")
        if not matches:
            continue
        servlets.append({"class": stem, "url_pattern": servlet.url_pattern, "file": relative})

    if query.startswith("/") and servlets:
        # Servlet dispatch chooses one mapping tier, not every matching
        # servlet. A guard on a default servlet cannot protect an exact route.
        best = max(_servlet_priority(str(entry["url_pattern"]), query) for entry in servlets)
        servlets = [
            entry
            for entry in servlets
            if _servlet_priority(str(entry["url_pattern"]), query) == best
        ]

    route_urls = [query] if query.startswith("/") else [str(s["url_pattern"]) for s in servlets]
    filters = [
        {"class": entry.class_name.rsplit(".", 1)[-1], "url_pattern": entry.url_pattern}
        for entry in index.filters
        if entry.class_name.rsplit(".", 1)[-1] == query
        or any(_url_matches(entry.url_pattern, url) for url in route_urls)
    ]

    auth_check = False
    auth_files = [str(entry["file"]) for entry in servlets]
    auth_files.extend(files_by_stem.get(str(entry["class"]), "") for entry in filters)
    for relative in auth_files:
        if not relative:
            continue
        try:
            text = ws.resolve(relative).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if ROLE_CHECK.search(text):
            auth_check = True
            break

    return {
        "servlets": servlets,
        "filters": filters,
        "auth_check": auth_check,
        "filter_match": "request_url" if query.startswith("/") else "servlet_pattern",
    }


def _url_matches(pattern: str, url: str, *, default: bool = False) -> bool:
    """Servlet-style exact, path-prefix and extension URL mappings."""
    if pattern == url or (default and pattern == "/"):
        return True
    if pattern.endswith("/*"):
        prefix = pattern[:-2]
        return url == prefix or url.startswith(prefix + "/")
    if pattern.startswith("*."):
        return url.rsplit("/", 1)[-1].endswith(pattern[1:])
    return False


def _servlet_priority(pattern: str, url: str) -> tuple[int, int]:
    if pattern == url:
        return 3, len(pattern)
    if pattern.endswith("/*"):
        return 2, len(pattern)
    if pattern.startswith("*."):
        return 1, len(pattern)
    return 0, 0
