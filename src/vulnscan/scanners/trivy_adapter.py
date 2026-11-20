"""Trivy adapter — IaC, Dockerfile, Kubernetes, and configuration security audit.

Runs ``trivy config --format json`` (or ``trivy fs --scanners misconfig``) and
parses the JSON report into normalized :class:`Observation` and
:class:`CoverageRecord` objects.

Missing binary handling: when ``trivy`` is not on PATH the adapter returns a
``skipped`` envelope with actionable install guidance — never raising.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    CWECategory,
    ExtractionMode,
    LanguageKind,
    Observation,
    RunStatus,
    ScannerResult,
    ScanSpecification,
    Severity,
    SourceCoordinate,
    ToolName,
    language_from_extension,
)

from .base import AdapterCapability, ScannerAdapter
from .mapping import parse_cwe_labels
from .platform import which
from .tool_versions import probe_version

ADAPTER_VERSION = "0.1.0"

_MISSING_BINARY_REASON = (
    "trivy not found on PATH; install Trivy "
    "(https://aquasecurity.github.io/trivy/) to enable IaC/Dockerfile/K8s config audits"
)

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def _map_severity(raw: str | None) -> Severity:
    if not raw:
        return Severity.MEDIUM
    return _SEVERITY_MAP.get(raw.strip().upper(), Severity.UNDETERMINED)


def parse_trivy_json(
    report: dict[str, Any],
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse a Trivy JSON report (``trivy config`` / ``trivy fs``) into observations."""
    now = datetime.now(UTC)
    observations: list[Observation] = []
    coverage: list[CoverageRecord] = []

    results = report.get("Results") or []
    if not isinstance(results, list):
        return observations, coverage

    for entry in results:
        if not isinstance(entry, dict):
            continue
        target = str(entry.get("Target") or "unknown")
        lang = language_from_extension(target)

        coverage.append(
            CoverageRecord(
                run_id=run_id,
                tool=ToolName.TRIVY,
                tool_version=tool_version,
                source_snapshot=source_snapshot,
                unit_path=target,
                unit_language=lang,
                eligible=True,
                status=CoverageUnitStatus.ANALYZED,
                extraction_mode=ExtractionMode.PATTERN,
                cwe_capabilities=[CWECategory.SECURITY_MISCONFIGURATION],
                cwe_limitations=[],
                analyzed_at=now,
            )
        )

        # Misconfigurations (Dockerfile, Kubernetes, Terraform, CI YAML, etc.)
        for misconf in entry.get("Misconfigurations") or []:
            if not isinstance(misconf, dict):
                continue
            status = str(misconf.get("Status") or "FAIL").upper()
            if status == "PASS":
                continue
            rule_id = str(misconf.get("AVDID") or misconf.get("ID") or "trivy-misconfig")
            title = str(misconf.get("Title") or misconf.get("Message") or rule_id)
            resolution = str(misconf.get("Resolution") or "")
            message = f"{title}. {resolution}".strip() if resolution else title
            cause = misconf.get("CauseMetadata") or {}
            start_line = max(int(cause.get("StartLine") or 1), 1)
            end_line = max(int(cause.get("EndLine") or start_line), start_line)

            code_lines = []
            for line_obj in (cause.get("Code") or {}).get("Lines") or []:
                if isinstance(line_obj, dict) and line_obj.get("Content") is not None:
                    code_lines.append(str(line_obj["Content"]))
            snippet = "\n".join(code_lines)[:1000] if code_lines else None

            observations.append(
                Observation(
                    observation_id="obs-"
                    + hashlib.sha256(f"{rule_id}|{target}|{start_line}".encode()).hexdigest()[:16],
                    run_id=run_id,
                    tool=ToolName.TRIVY,
                    tool_version=tool_version,
                    rule_id=rule_id,
                    cwe_category=CWECategory.SECURITY_MISCONFIGURATION,
                    severity=_map_severity(misconf.get("Severity")),
                    native_severity=str(misconf.get("Severity") or "MEDIUM"),
                    message=message[:1000],
                    location=SourceCoordinate(
                        file_path=target,
                        language=lang,
                        line_start=start_line,
                        line_end=end_line,
                        snippet=snippet,
                    ),
                    detected_at=now,
                    metadata={
                        "type": entry.get("Type") or misconf.get("Type") or "config",
                        "primary_url": misconf.get("PrimaryURL") or "",
                        "resolution": resolution[:500],
                    },
                )
            )

        # Optional Vulnerabilities block when invoked in fs mode
        for vuln in entry.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("VulnerabilityID") or "unknown")
            pkg_name = str(vuln.get("PkgName") or "unknown")
            installed = str(vuln.get("InstalledVersion") or "")
            fixed = str(vuln.get("FixedVersion") or "")
            dep_id = f"{pkg_name}@{installed}" if installed else pkg_name
            cwes = parse_cwe_labels(vuln.get("CweIDs") or [])
            from .mapping import cwe_category as _cwe_category

            cwe = (_cwe_category(cwes[0]) if cwes else None) or CWECategory.DEPENDENCY_VULNERABILITY
            title = str(vuln.get("Title") or vuln.get("Description") or vuln_id)
            if fixed:
                title = f"{title} (fixed in {fixed})"

            observations.append(
                Observation(
                    observation_id="obs-"
                    + hashlib.sha256(f"{vuln_id}|{target}|{dep_id}".encode()).hexdigest()[:16],
                    run_id=run_id,
                    tool=ToolName.TRIVY,
                    tool_version=tool_version,
                    rule_id=vuln_id,
                    cwe_category=cwe,
                    severity=_map_severity(vuln.get("Severity")),
                    native_severity=str(vuln.get("Severity") or "MEDIUM"),
                    message=title[:1000],
                    location=SourceCoordinate(
                        file_path=target,
                        language=LanguageKind.OTHER,
                        line_start=1,
                    ),
                    dependency_identity=dep_id,
                    detected_at=now,
                    metadata={
                        "package": pkg_name,
                        "installed_version": installed,
                        "fixed_version": fixed,
                        "primary_url": vuln.get("PrimaryURL") or "",
                    },
                )
            )

    return observations, coverage


class TrivyAdapter(ScannerAdapter):
    """Trivy adapter for IaC, Dockerfile, Kubernetes, and config security audits."""

    tool = ToolName.TRIVY
    binary_name = "trivy"
    adapter_version = ADAPTER_VERSION
    default_timeout: float = 300.0

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

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        started = datetime.now(UTC)
        tool_cfg = self._tool_config(spec)

        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        cap = self.capabilities()
        if not cap.available:
            return ScannerResult(
                run_id=spec.run_id or "unassigned",
                tool=self.tool,
                tool_version="unknown",
                adapter_version=self.adapter_version,
                status=RunStatus.SKIPPED,
                started_at=started,
                finished_at=started,
                errors=[cap.unavailable_message()],
            )

        target = "."
        if tool_cfg and isinstance(tool_cfg.options, dict):
            tp = tool_cfg.options.get("target_path")
            if isinstance(tp, str) and tp.strip():
                candidate = (Path(workdir) / tp.strip()).resolve()
                try:
                    rel = candidate.relative_to(Path(workdir).resolve()).as_posix()
                    if candidate.exists():
                        target = rel or "."
                except ValueError:
                    pass

        argv = [
            self.binary_name,
            "config",
            "--format",
            "json",
            "--quiet",
            target,
        ]
        result = self._invoke(argv, cwd=workdir)
        finished = datetime.now(UTC)

        if result.timed_out or result.returncode not in (0, 1):
            return self._fatal(spec, started, finished, result, note="trivy config audit failed")

        raw = result.stdout.strip()
        if not raw:
            return ScannerResult(
                run_id=spec.run_id or "unassigned",
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
                metadata={"misconfigurations_found": 0},
            )

        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise TypeError("trivy report must be a JSON object")
        except (ValueError, TypeError):
            return self._fatal(
                spec, started, finished, result, note="trivy output is not valid JSON"
            )

        observations, coverage = parse_trivy_json(
            data,
            run_id=spec.run_id or "unassigned",
            tool_version=cap.version or "unknown",
            source_snapshot=spec.target_commit_sha,
        )
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=self.tool,
            tool_version=cap.version or "unknown",
            adapter_version=self.adapter_version,
            status=RunStatus.COMPLETED,
            started_at=started,
            finished_at=finished,
            observations=observations,
            coverage_records=coverage,
            raw_output_refs=[],
            eligible_units=len(coverage),
            analyzed_units=len(coverage),
            skipped_units=0,
            failed_units=0,
            errors=[],
            warnings=[],
            duration_ms=result.duration_ms,
            metadata={"misconfigurations_found": len(observations)},
        )


__all__ = ["TrivyAdapter", "parse_trivy_json"]
