"""OWASP Dependency-Check adapter — dependency-track analysis.

Parses the Dependency-Check JSON report (``--format JSON``).  Missing
binary, missing report file, and virtual dependencies are all documented
conditions: the adapter records them and returns a result, never raising.
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
from .process import CommandResult
from .tool_versions import probe_version

_SEVERITY_BY_NAME = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _cvss_to_severity(score: float | None) -> Severity | None:
    """CVSS v3 base score -> contract Severity (None when undeterminable)."""
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.1:
        return Severity.LOW
    return Severity.INFO


def _name_to_severity(name: str | None) -> Severity | None:
    if not name:
        return None
    return _SEVERITY_BY_NAME.get(name.strip().lower())


def _extract_cwe(vuln: dict[str, Any]) -> CWECategory | None:
    """Pull the first supported CWE id out of a Dependency-Check vuln entry."""
    raw = vuln.get("cwes") or vuln.get("cwe") or []
    if isinstance(raw, (str, int)):
        raw = [raw]
    for value in raw:
        text = str(value).strip().upper()
        if not text:
            continue
        if not text.startswith("CWE-"):
            text = f"CWE-{text}"
        try:
            return CWECategory(text)
        except ValueError:
            continue
    return None


def parse_dependency_check_json(
    report: dict[str, Any],
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse a Dependency-Check JSON report into observations + coverage."""
    now = datetime.now(timezone.utc)
    observations: list[Observation] = []
    coverage: list[CoverageRecord] = []

    for dep in report.get("dependencies", []):
        dep_name = dep.get("fileName") or dep.get("name") or "unknown"
        is_virtual = bool(dep.get("isVirtual", False))
        evidence = dep.get("evidenceCollected", {}) or {}
        vendor_count = len(evidence.get("vendorEvidence", []) or [])
        product_count = len(evidence.get("productEvidence", []) or [])

        unit_status = CoverageUnitStatus.SKIPPED if is_virtual else CoverageUnitStatus.ANALYZED
        coverage.append(
            CoverageRecord(
                run_id=run_id,
                tool=ToolName.OWASP_DEPENDENCY_CHECK,
                tool_version=tool_version,
                source_snapshot=source_snapshot,
                unit_path=dep_name,
                unit_language=LanguageKind.OTHER,
                eligible=True,
                status=unit_status,
                limitation_reason=(
                    "virtual dependency: no local artifact to scan"
                    if is_virtual
                    else None
                ),
                extraction_mode=ExtractionMode.DEPENDENCY_GRAPH,
                diagnostics=[f"evidence: {vendor_count} vendor, {product_count} product"],
                unresolved_calls=[],
                cwe_capabilities=[CWECategory.CWE_1104],
                cwe_limitations=[],
                confidence_floor=0.6,
            )
        )

        for vuln in dep.get("vulnerabilities", []) or []:
            vuln_id = str(vuln.get("name") or "unknown")
            description = str(vuln.get("description") or "")
            cvss = vuln.get("cvssv3") or vuln.get("cvssv2") or {}
            score = cvss.get("baseScore") if isinstance(cvss, dict) else None
            severity = _cvss_to_severity(score) or _name_to_severity(vuln.get("severity"))

            observations.append(
                Observation(
                    run_id=run_id,
                    tool=ToolName.OWASP_DEPENDENCY_CHECK,
                    tool_version=tool_version,
                    rule_id=vuln_id,
                    cwe_category=_extract_cwe(vuln),
                    severity=severity or Severity.UNDETERMINED,
                    native_severity=f"cvss={score}" if score is not None else "undetermined",
                    message=description[:1000],
                    location=SourceCoordinate(
                        file_path=dep_name,
                        language=LanguageKind.OTHER,
                        line_start=1,
                    ),
                    dependency_identity=dep_name,
                    detected_at=now,
                    metadata={"cvss": score, "vulnerability_id": vuln_id},
                )
            )

    return observations, coverage


class DependencyCheckAdapter(ScannerAdapter):
    """OWASP Dependency-Check adapter (dependency track)."""

    tool = ToolName.OWASP_DEPENDENCY_CHECK
    binary_name = "dependency-check"
    default_timeout: float = 900.0

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

        report_path = Path(workdir) / "dependency-check-report.json"
        argv = [
            self.binary_name,
            "--scan",
            workdir,
            "--format",
            "JSON",
            "--out",
            str(report_path.parent),
            "--noupdate",
        ]
        if tool_cfg:
            for key, value in (tool_cfg.options or {}).items():
                argv += [f"--{key}", str(value)]

        result = self._invoke(argv, cwd=workdir)
        finished = datetime.now(timezone.utc)

        if not report_path.exists():
            return self._fatal(
                spec, started, finished, result, note="dependency-check produced no report"
            )

        try:
            report = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            return self._fatal(
                spec, started, finished, result, note=f"unreadable dependency-check report: {exc}"
            )

        observations, coverage_records = parse_dependency_check_json(
            report,
            run_id=spec.run_id,
            tool_version=cap.version or "unknown",
            source_snapshot=spec.target_commit_sha,
        )

        skipped = sum(1 for c in coverage_records if c.status == CoverageUnitStatus.SKIPPED)
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
            analyzed_units=len(coverage_records) - skipped,
            skipped_units=skipped,
            failed_units=0,
            errors=[],
            warnings=[],
            duration_ms=result.duration_ms,
            metadata={},
        )


__all__ = ["DependencyCheckAdapter", "parse_dependency_check_json"]
