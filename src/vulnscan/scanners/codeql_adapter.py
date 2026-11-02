"""CodeQL adapter — opt-in DEEP dataflow step.

Runs ``codeql database create`` (cached under ``artifacts/codeql-db/<commit>``
and reused when a database marker is present) followed by
``codeql database analyze`` with the security-extended suite, then parses the
SARIF report into normalized observations.

Missing binary handling: when ``codeql`` is not on PATH the adapter returns a
``skipped`` envelope with an actionable install reason — never a failure and
never an exception. Query-pack/bundle download and live CI wiring are
explicitly out of scope for this slice.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    CWECategory,
    ExtractionMode,
    Observation,
    RunStatus,
    ScannerResult,
    ScanSpecification,
    SourceCoordinate,
    ToolName,
    language_from_extension,
)

from .base import AdapterCapability, ScannerAdapter
from .mapping import cwe_category, map_severity, parse_cwe_labels
from .platform import which
from .process import CommandResult
from .tool_versions import probe_version

ADAPTER_VERSION = "0.3.0"

#: Marker file CodeQL writes inside a successfully created database directory.
_DB_MARKER = "codeql-database.yml"

#: Languages this adapter can request from ``codeql database create``.
_SUPPORTED_LANGUAGES = ("java", "javascript")

#: Install guidance surfaced whenever the binary is absent.
_MISSING_BINARY_REASON = (
    "codeql not found on PATH; install the CodeQL CLI bundle "
    "(https://github.com/github/codeql-cli-binaries) and ensure 'codeql' is "
    "on PATH, or leave this opt-in DEEP step disabled in the scan spec"
)

_JSP_SUFFIXES = (".jsp", ".jspx")


def _safe_commit(sha: str | None) -> str:
    """Sanitize a commit SHA for use as a cache directory name."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", (sha or "unknown"))[:64]
    return cleaned or "unknown"


def _codeql_languages(spec: ScanSpecification) -> list[str]:
    """Resolve which CodeQL languages to analyze for *spec*."""
    tool_cfg = next((c for c in spec.tools if c.tool == ToolName.CODEQL), None)
    options = dict(getattr(tool_cfg, "options", None) or {})
    override = options.get("languages") or options.get("language")
    if override:
        wanted = [override] if isinstance(override, str) else list(override)
        return [str(w).lower() for w in wanted if str(w).lower() in _SUPPORTED_LANGUAGES] or [
            "java"
        ]
    lang = (spec.language or "java").lower()
    if lang in ("javascript", "typescript", "js", "ts"):
        return ["javascript"]
    return ["java"]


def _suite_for(language: str, spec: ScanSpecification) -> str:
    """Query suite for *language*; overridable via tool options."""
    tool_cfg = next((c for c in spec.tools if c.tool == ToolName.CODEQL), None)
    options = dict(getattr(tool_cfg, "options", None) or {})
    override = options.get("suite")
    if isinstance(override, str) and override.strip():
        return override.strip()
    return f"{language}-security-extended.qls"


def _database_root(spec: ScanSpecification) -> Path:
    """Cache root ``artifacts/codeql-db/<commit>`` for this run."""
    tool_cfg = next((c for c in spec.tools if c.tool == ToolName.CODEQL), None)
    options = dict(getattr(tool_cfg, "options", None) or {})
    override = options.get("database_dir")
    if isinstance(override, str) and override.strip():
        return Path(override).expanduser()
    output_dir = spec.metadata.get("configuration", {}).get("output_dir", "artifacts")
    return Path(output_dir) / "codeql-db" / _safe_commit(spec.target_commit_sha)


def _observation_id(rule_id: str, file_path: str, line: int) -> str:
    blob = f"{rule_id}|{file_path}|{line}"
    return "obs-" + hashlib.sha1(blob.encode()).hexdigest()[:16]


def _strip_file_uri(uri: str) -> str:
    """SARIF artifact URIs may be ``file://`` URIs; keep a plain relative path."""
    if uri.startswith("file://"):
        return uri[len("file://") :]
    return uri


def parse_codeql_sarif(
    text: str,
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse a CodeQL SARIF report into observations and per-file coverage.

    Pure function: takes already-fetched text so tests drive fixtures through
    it without a subprocess. ``rule_id`` comes from the SARIF rule id, CWE
    from the rule tags, and the snippet from the result region.
    """
    sarif = json.loads(text)
    if not isinstance(sarif, dict):
        raise TypeError("CodeQL SARIF report must be a JSON object")
    now = datetime.now(UTC)
    observations: list[Observation] = []

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", []) or []
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict) and r.get("id")}
        rule_ver = driver.get("semanticVersion", tool_version)

        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            rule: dict[str, Any] = {}
            rule_id = result.get("ruleId")
            if isinstance(rule_id, str) and rule_id in by_id:
                rule = by_id[rule_id]
            else:
                index = result.get("ruleIndex")
                if isinstance(index, int) and 0 <= index < len(rules):
                    rule = rules[index] if isinstance(rules[index], dict) else {}
                rule_id = rule.get("id", result.get("ruleId", "unknown"))
            if not isinstance(rule_id, str) or not rule_id:
                rule_id = "unknown"

            locations = result.get("locations", []) or []
            if not locations or not isinstance(locations[0], dict):
                continue
            phys = locations[0].get("physicalLocation", {}) or {}
            artifact = phys.get("artifactLocation", {}) or {}
            file_path = _strip_file_uri(str(artifact.get("uri", "")))
            if not file_path:
                continue
            region = phys.get("region", {}) or {}
            try:
                line_start = int(region.get("startLine", 1))
            except (TypeError, ValueError):
                line_start = 1
            line_start = max(line_start, 1)
            try:
                line_end = int(region.get("endLine", line_start))
            except (TypeError, ValueError):
                line_end = line_start
            snippet = region.get("snippet", {}) or {}
            snippet_text = snippet.get("text") if isinstance(snippet, dict) else None

            tags = (rule.get("properties", {}) or {}).get("tags", [])
            cwe_cat: CWECategory | None = None
            for label in parse_cwe_labels(tags):
                cwe_cat = cwe_category(label)
                if cwe_cat is not None:
                    break

            level = str(result.get("level", "warning"))
            message = result.get("message", {}) or {}
            observations.append(
                Observation(
                    observation_id=_observation_id(rule_id, file_path, line_start),
                    run_id=run_id,
                    tool=ToolName.CODEQL,
                    tool_version=rule_ver,
                    rule_id=rule_id,
                    cwe_category=cwe_cat,
                    severity=map_severity(level),
                    native_severity=level,
                    message=str(message.get("text", ""))[:1000],
                    location=SourceCoordinate(
                        file_path=file_path,
                        language=language_from_extension(file_path),
                        line_start=line_start,
                        line_end=line_end or line_start,
                        column_start=region.get("startColumn"),
                        column_end=region.get("endColumn"),
                        snippet=str(snippet_text)[:1000] if snippet_text else None,
                    ),
                    detected_at=now,
                    metadata={"codeql_rule_index": result.get("ruleIndex")},
                )
            )

    coverage: list[CoverageRecord] = []
    seen: dict[str, list[CWECategory | None]] = {}
    for obs in observations:
        seen.setdefault(obs.location.file_path, []).append(obs.cwe_category)
    for file_path, cwes in sorted(seen.items()):
        capabilities = sorted({c for c in cwes if c is not None}, key=lambda c: c.value)
        coverage.append(
            CoverageRecord(
                run_id=run_id,
                tool=ToolName.CODEQL,
                tool_version=tool_version,
                source_snapshot=source_snapshot,
                unit_path=file_path,
                unit_language=language_from_extension(file_path),
                eligible=True,
                status=CoverageUnitStatus.ANALYZED,
                extraction_mode=ExtractionMode.DATAFLOW,
                cwe_capabilities=capabilities,
                analyzed_at=now,
            )
        )
    return observations, coverage


class CodeQLAdapter(ScannerAdapter):
    """CodeQL adapter: cached database create + security-extended analyze."""

    tool = ToolName.CODEQL
    binary_name = "codeql"
    adapter_version = ADAPTER_VERSION

    def capabilities(self) -> AdapterCapability:
        resolved = which(self.binary_name)
        version = probe_version(self.binary_name) if resolved else None
        return AdapterCapability(
            tool=self.tool,
            binary=self.binary_name,
            version=version,
            available=resolved is not None,
            reason=None if resolved else _MISSING_BINARY_REASON,
        )

    def _skipped_missing_binary(self, spec: ScanSpecification, started_at: Any) -> ScannerResult:
        """Skipped envelope for the absent-binary case (never a failure)."""
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=self.tool,
            tool_version="unknown",
            adapter_version=self.adapter_version,
            status=RunStatus.SKIPPED,
            started_at=started_at,
            finished_at=started_at,
            errors=[_MISSING_BINARY_REASON],
            warnings=["CodeQL is an opt-in DEEP step; skipping it leaves baseline coverage unchanged"],
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        started = datetime.now(UTC)
        tool_cfg = self._tool_config(spec)

        if tool_cfg is not None and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        cap = self.capabilities()
        if not cap.available:
            return self._skipped_missing_binary(spec, started)

        languages = _codeql_languages(spec)
        db_root = _database_root(spec)
        successes: dict[str, bool] = {}
        for language in languages:
            db_dir = db_root / language
            if not self._ensure_database(db_dir, language, workdir):
                finished = datetime.now(UTC)
                return self._fatal(
                    spec,
                    started,
                    finished,
                    CommandResult(
                        returncode=1,
                        stderr=f"database create failed for {db_dir}",
                        command=("codeql", "database", "create"),
                    ),
                    note=f"codeql database create failed for language '{language}'",
                )
            successes[language] = (db_dir / _DB_MARKER).is_file()

        with tempfile.TemporaryDirectory(prefix="vulnscan-codeql-") as temporary:
            sarif_path = Path(temporary) / "codeql-results.sarif"
            argv: list[str] = [
                self.binary_name,
                "database",
                "analyze",
                *[str(db_root / language) for language in languages],
                "--format=sarif-latest",
                f"--output={sarif_path}",
                *[_suite_for(language, spec) for language in languages],
            ]
            result = self._invoke(argv, cwd=workdir)
            finished = datetime.now(UTC)
            if result.timed_out or not result.succeeded or not sarif_path.is_file():
                return self._fatal(
                    spec, started, finished, result, note="codeql database analyze failed"
                )
            try:
                observations, coverage_records = parse_codeql_sarif(
                    sarif_path.read_text(encoding="utf-8"),
                    run_id=spec.run_id or "unassigned",
                    tool_version=cap.version or "unknown",
                    source_snapshot=spec.target_commit_sha,
                )
            except (ValueError, TypeError, OSError, UnicodeDecodeError) as exc:
                return self._fatal(
                    spec,
                    started,
                    finished,
                    CommandResult(
                        returncode=1,
                        stderr=f"invalid CodeQL SARIF: {exc}",
                        command=tuple(argv),
                    ),
                    note="invalid CodeQL SARIF report",
                )

        warnings: list[str] = []
        inventory = spec.metadata.get("manifest", {}).get("inventory", [])
        if any(str(p).lower().endswith(_JSP_SUFFIXES) for p in inventory):
            warnings.append("JSP sources sit outside the CodeQL database; no JSP coverage is claimed")

        analyzed = sum(1 for c in coverage_records if c.status == CoverageUnitStatus.ANALYZED)
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=self.tool,
            tool_version=cap.version or "unknown",
            adapter_version=self.adapter_version,
            status=RunStatus.COMPLETED,
            started_at=started,
            finished_at=finished,
            observations=observations,
            coverage_records=coverage_records,
            eligible_units=len(coverage_records),
            analyzed_units=analyzed,
            errors=[],
            warnings=warnings,
            duration_ms=result.duration_ms,
            metadata={
                "codeql_database": str(db_root),
                "codeql_db_reused": successes,
                "codeql_languages": languages,
            },
        )

    def _ensure_database(self, db_dir: Path, language: str, workdir: str) -> bool:
        """Create the CodeQL database unless a cached one is present."""
        if (db_dir / _DB_MARKER).is_file():
            return True
        if db_dir.exists():
            try:
                shutil.rmtree(db_dir)
            except OSError:
                return False
        create = self._invoke(
            [
                self.binary_name,
                "database",
                "create",
                str(db_dir),
                f"--language={language}",
                f"--source-root={workdir}",
            ],
            cwd=workdir,
        )
        return create.succeeded and (db_dir / _DB_MARKER).is_file()


__all__ = ["ADAPTER_VERSION", "CodeQLAdapter", "parse_codeql_sarif"]
