"""Native-hunt adapter — our own regex+taint engine as a first-class scanner.

Runs :mod:`vulnscan.native_hunt` (no external binary) over the snapshot and
maps its findings to observations. This is the in-house "tool hunt" lane:
model hunt explores, native hunt verifies with deterministic rules, and
the Laya router + validator adjudicate. Semgrep/SpotBugs remain available
as baseline oracles, not as the primary evidence source.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

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
from vulnscan.native_hunt import FAMILY_EXTENSIONS, scan_snapshot
from vulnscan.scanners.mapping import cwe_category

from .base import AdapterCapability, ScannerAdapter

TOOL_VERSION = "1.0"

_SEVERITY_MAP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM}

_CONFIDENCE_MAP = {"High": 0.9, "Medium": 0.6, "Weak": 0.3}


def _observation_id(run_id: str, file: str, line: int, rule_id: str) -> str:
    digest = hashlib.sha256(f"{run_id}:{file}:{line}:{rule_id}".encode()).hexdigest()
    return f"native-hunt-{digest[:16]}"


def _language_for(path: str) -> LanguageKind:
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if suffix in {".java", ".jsp", ".jspx"}:
        return LanguageKind.JAVA
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"}:
        return LanguageKind.JAVASCRIPT
    if suffix == ".py":
        return LanguageKind.PYTHON
    if suffix in {".php", ".phtml"}:
        return LanguageKind.PHP
    if suffix == ".go":
        return LanguageKind.GO
    if suffix in {".rb", ".erb"}:
        return LanguageKind.RUBY
    if suffix in {".cs", ".cshtml", ".razor"}:
        return LanguageKind.CSHARP
    return LanguageKind.OTHER


class NativeHuntAdapter(ScannerAdapter):
    """In-house pattern+taint scanner. No binary, always available."""

    tool = ToolName.NATIVE_HUNT
    binary_name = "native-hunt"

    def capabilities(self) -> AdapterCapability:
        return AdapterCapability(
            tool=self.tool,
            binary=self.binary_name,
            version=TOOL_VERSION,
            available=True,
            reason=None,
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        started = datetime.now(UTC)
        run_id = spec.run_id or "unassigned"
        try:
            result = scan_snapshot(workdir, list(FAMILY_EXTENSIONS))
        except Exception as exc:  # noqa: BLE001 - adapter never raises
            finished = datetime.now(UTC)
            return ScannerResult(
                run_id=run_id,
                tool=self.tool,
                tool_version=TOOL_VERSION,
                adapter_version=self.adapter_version,
                status=RunStatus.FAILED,
                started_at=started,
                finished_at=finished,
                observations=[],
                errors=[f"native-hunt engine failed: {type(exc).__name__}"],
            )
        finished = datetime.now(UTC)
        observations: list[Observation] = []
        for finding in result.findings:
            observations.append(
                Observation(
                    observation_id=_observation_id(
                        run_id, finding.file, finding.line, finding.rule_id
                    ),
                    run_id=run_id,
                    tool=self.tool,
                    tool_version=TOOL_VERSION,
                    rule_id=finding.rule_id,
                    cwe_category=cwe_category(f"CWE-{finding.cwe}")
                    if finding.cwe
                    else None,
                    severity=_SEVERITY_MAP.get(
                        finding.severity.upper(), Severity.MEDIUM
                    ),
                    native_severity=finding.severity,
                    message=f"{finding.rule_id}: {finding.message or finding.attack}",
                    confidence=_CONFIDENCE_MAP.get(finding.confidence, 0.3),
                    location=SourceCoordinate(
                        file_path=finding.file,
                        language=_language_for(finding.file),
                        line_start=finding.line,
                        line_end=finding.line,
                        snippet=finding.snippet,
                    ),
                    detected_at=finished,
                    metadata={
                        "attack": finding.attack,
                        "confidence_label": finding.confidence,
                    },
                )
            )
        coverage: list[CoverageRecord] = []
        for path in result.scanned:
            coverage.append(
                CoverageRecord(
                    run_id=run_id,
                    tool=self.tool,
                    tool_version=TOOL_VERSION,
                    source_snapshot=spec.target_commit_sha,
                    unit_path=path,
                    unit_language=_language_for(path),
                    eligible=True,
                    status=CoverageUnitStatus.ANALYZED,
                    extraction_mode=ExtractionMode.PATTERN,
                    analyzed_at=finished,
                )
            )
        for skipped in result.skipped:
            path = skipped.split(" (", 1)[0]
            reason = skipped.split(" (", 1)[1].rstrip(")") if " (" in skipped else "skipped"
            coverage.append(
                CoverageRecord(
                    run_id=run_id,
                    tool=self.tool,
                    tool_version=TOOL_VERSION,
                    source_snapshot=spec.target_commit_sha,
                    unit_path=path,
                    unit_language=_language_for(path),
                    eligible=True,
                    status=CoverageUnitStatus.UNSUPPORTED,
                    limitation_reason=reason,
                    analyzed_at=finished,
                )
            )
        return ScannerResult(
            run_id=run_id,
            tool=self.tool,
            tool_version=TOOL_VERSION,
            adapter_version=self.adapter_version,
            status=RunStatus.COMPLETED,
            started_at=started,
            finished_at=finished,
            observations=observations,
            coverage_records=coverage,
            raw_output_refs=[],
            eligible_units=len(coverage),
            analyzed_units=sum(1 for c in coverage if c.status == CoverageUnitStatus.ANALYZED),
            skipped_units=sum(
                1 for c in coverage if c.status == CoverageUnitStatus.UNSUPPORTED
            ),
            failed_units=0,
            errors=[],
        )
