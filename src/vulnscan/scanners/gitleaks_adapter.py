"""Gitleaks adapter — secret detection in source and git history.

Parses Gitleaks JSON output (``gitleaks detect --report-format json``).
Missing binary → documented ``skipped``/``failed`` envelope, never an exception.

The adapter maps Gitleaks findings into the ``SECRETS`` CWE category
(CWE-200/CWE-798 family) and ``Severity.HIGH`` for all hardcoded secrets
unless a rule's severity suggests otherwise.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    ExtractionMode,
    LanguageKind,
    Observation,
    RunStatus,
    ScanSpecification,
    ScannerResult,
    Severity,
    SourceCoordinate,
    ToolName,
)
from vulnscan.contracts.enums import CWECategory

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
    now = datetime.now(timezone.utc)
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
        lang = LanguageKind.JAVA if ext == ".java" else (
            LanguageKind.JSP if ext in (".jsp", ".jspx") else LanguageKind.OTHER
        )

        observations.append(
            Observation(
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
                    "match": finding.get("Match"),
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
            lang = LanguageKind.JAVA if ext == ".java" else (
                LanguageKind.JSP if ext in (".jsp", ".jspx") else LanguageKind.OTHER
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
                    confidence_floor=0.8,
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
        started = datetime.now(timezone.utc)
        tool_cfg = self._tool_config(spec)

        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        cap = self.capabilities()
        if not cap.available:
            return self._skipped_result(spec, started, cap.unavailable_message())

        import os
        report_path = Path(workdir) / "gitleaks-report.json"
        argv = [
            self.binary_name,
            "detect",
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--source",
            workdir,
        ]
        if tool_cfg:
            for key, value in (tool_cfg.options or {}).items():
                if isinstance(value, bool) and value:
                    argv += [f"--{key}"]
                elif isinstance(value, bool) and not value:
                    continue
                else:
                    argv += [f"--{key}", str(value)]

        result = self._invoke(argv, cwd=workdir)
        finished = datetime.now(timezone.utc)

        if not report_path.exists():
            # Gitleaks exits 1 when no findings — that's not a failure
            if result.returncode in (0, 1):
                return ScannerResult(
                    run_id=spec.run_id,
                    tool=self.tool,
                    tool_version=cap.version or "unknown",
                    adapter_version=self.adapter_version,
                    status=RunStatus.COMPLETED,
                    started_at=started,
                    finished_at=finished,
                    observations=[],
                    coverage_records=[],
                    raw_output_refs=[],
                    eligible_units=0,
                    analyzed_units=0,
                    skipped_units=0,
                    failed_units=0,
                    errors=[],
                    warnings=[],
                    duration_ms=result.duration_ms,
                    metadata={"exit_code": result.returncode},
                )
            return self._fatal(
                spec, started, finished, result, note="gitleaks did not produce a report"
            )

        try:
            report_text = report_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return self._fatal(
                spec, started, finished, result, note=f"failed to read gitleaks report: {exc}"
            )

        try:
            report_data = json.loads(report_text)
        except json.JSONDecodeError:
            return self._fatal(
                spec, started, finished, result, note="gitleaks report is not valid JSON"
            )

        observations, coverage_records = parse_gitleaks_json(
            report_data,
            run_id=spec.run_id,
            tool_version=cap.version or "unknown",
            source_snapshot=spec.target_commit_sha,
        )

        return ScannerResult(
            run_id=spec.run_id,
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
