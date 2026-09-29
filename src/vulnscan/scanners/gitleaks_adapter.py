"""Gitleaks adapter — secret detection in source and git history.

Parses Gitleaks JSON output (``gitleaks detect --report-format json``).
Missing binary → documented ``skipped``/``failed`` envelope, never an exception.

The adapter maps Gitleaks findings into the ``SECRETS`` CWE category
(CWE-200/CWE-798 family) and ``Severity.HIGH`` for all hardcoded secrets
unless a rule's severity suggests otherwise.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    ExtractionMode,
    LanguageKind,
    Observation,
    RunStatus,
    ScannerResult,
    ScanSpecification,
    Severity,
    SourceCoordinate,
    ToolName,
)

from .base import AdapterCapability, ScannerAdapter
from .platform import which
from .tool_versions import probe_version

# --- severity mapping ----------------------------------------------------- #

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _default_severity() -> Severity:
    """Default: hardcoded secrets are high-risk unless the rule says otherwise."""
    return Severity.HIGH


def parse_gitleaks_json(
    report: dict[str, Any] | list[dict[str, Any]],
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse Gitleaks JSON output.

    Handles both the single-key ``{"results": [...]}`` envelope and
    the raw ``[...]`` array form.
    """
    if isinstance(report, dict):
        findings = report.get("results", [])
    else:
        findings = report
    now = datetime.now(UTC)
    observations: list[Observation] = []
    coverage: list[CoverageRecord] = []

    for finding in findings:
        rule_id = finding.get("RuleID", finding.get("ruleId", "unknown"))
        description = finding.get("Description", rule_id)
        raw_sev = (finding.get("Severity") or "").lower()
        sev = _SEVERITY_MAP.get(raw_sev, _default_severity())
        file_path = finding.get("File") or finding.get("file", "")
        line_start = int(finding.get("StartLine") or finding.get("startLine") or 1)
        line_end = int(finding.get("EndLine") or finding.get("endLine") or line_start)
        author = finding.get("Author", "")
        commit = finding.get("Commit", "")

        ext = Path(file_path).suffix.lower()
        lang = (
            LanguageKind.JAVA
            if ext == ".java"
            else (LanguageKind.JSP if ext in (".jsp", ".jspx") else LanguageKind.OTHER)
        )

        observations.append(
            Observation(
                observation_id="obs-"
                + hashlib.sha256(f"{rule_id}|{file_path}|{line_start}".encode()).hexdigest()[:16],
                run_id=run_id,
                tool=ToolName.GITLEAKS,
                tool_version=tool_version,
                rule_id=rule_id,
                cwe_category=None,
                severity=sev,
                native_severity=raw_sev,
                message=f"Secret found: {description}",
                location=SourceCoordinate(
                    file_path=file_path,
                    language=lang,
                    line_start=line_start,
                    line_end=line_end,
                ),
                detected_at=now,
                metadata={
                    "commit": commit,
                    "author": author,
                    "match": "[REDACTED]",
                    "entropy": finding.get("Entropy"),
                },
            )
        )

    # Coverage: every file where a secret was found counts as analyzed
    seen_files: set[str] = set()
    for f in findings:
        fp = f.get("File") or f.get("file", "")
        if fp and fp not in seen_files:
            seen_files.add(fp)
            ext = Path(fp).suffix.lower()
            lang = (
                LanguageKind.JAVA
                if ext == ".java"
                else (LanguageKind.JSP if ext in (".jsp", ".jspx") else LanguageKind.OTHER)
            )
            coverage.append(
                CoverageRecord(
                    run_id=run_id,
                    tool=ToolName.GITLEAKS,
                    tool_version=tool_version,
                    source_snapshot=source_snapshot,
                    unit_path=fp,
                    unit_language=lang,
                    eligible=True,
                    status=CoverageUnitStatus.ANALYZED,
                    extraction_mode=ExtractionMode.PATTERN,
                    diagnostics=[],
                    unresolved_calls=[],
                    cwe_capabilities=[],
                    cwe_limitations=[],
                    analyzed_at=now,
                )
            )

    return observations, coverage


class GitleaksAdapter(ScannerAdapter):
    """Gitleaks secret-detection adapter."""

    tool = ToolName.GITLEAKS
    binary_name = "gitleaks"

    def capabilities(self) -> AdapterCapability:
        resolved = which(self.binary_name)
        version = probe_version(self.binary_name) if resolved else None
        return AdapterCapability(
            tool=self.tool,
            binary=self.binary_name,
            version=version,
            available=resolved is not None,
            reason=None if resolved else f"{self.binary_name} not found on PATH",
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        started = datetime.now(UTC)
        tool_cfg = self._tool_config(spec)

        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        cap = self.capabilities()
        if not cap.available:
            return self._skipped_result(spec, started, cap.unavailable_message())

        with tempfile.TemporaryDirectory(prefix="vulnscan-gitleaks-") as temporary:
            report_path = Path(temporary) / "report.json"
            argv = [
                self.binary_name,
                "detect",
                "--no-git",
                "--redact=100",
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--source",
                workdir,
            ]
            result = self._invoke(argv, cwd=workdir)
            finished = datetime.now(UTC)
            if result.timed_out or result.returncode not in (0, 1) or not report_path.is_file():
                return self._fatal(
                    spec, started, finished, result, note="gitleaks did not complete with a report"
                )
            try:
                report_data = json.loads(report_path.read_text(encoding="utf-8"))
                if not isinstance(report_data, list):
                    raise TypeError("expected a JSON array")
            except (TypeError, ValueError, OSError):
                return self._fatal(spec, started, finished, result, note="invalid gitleaks report")

        observations, coverage_records = parse_gitleaks_json(
            report_data,
            run_id=spec.run_id or "unassigned",
            tool_version=cap.version or "unknown",
            source_snapshot=spec.target_commit_sha,
        )

        coverage_records = [
            CoverageRecord(
                run_id=spec.run_id or "unassigned",
                tool=self.tool,
                tool_version=cap.version or "unknown",
                source_snapshot=spec.target_commit_sha,
                unit_path=path,
                unit_language=LanguageKind.JSP
                if path.lower().endswith(".jsp")
                else LanguageKind.JAVA,
                eligible=True,
                status=CoverageUnitStatus.ANALYZED,
                analyzed_at=finished,
                extraction_mode=ExtractionMode.TEXT,
            )
            for path in spec.metadata.get("manifest", {}).get("inventory", [])
        ]
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
            raw_output_refs=[],
            eligible_units=len(coverage_records),
            analyzed_units=len(coverage_records),
            skipped_units=0,
            failed_units=0,
            errors=[],
            warnings=[],
            duration_ms=result.duration_ms,
            metadata={"secrets_found": len(observations)},
        )


__all__ = ["GitleaksAdapter", "parse_gitleaks_json"]
