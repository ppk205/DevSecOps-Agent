"""Adapter OWASP Dependency-Check — phân tích theo nhánh dependency.

Phân tích cú pháp báo cáo JSON của Dependency-Check (``--format JSON``). Việc thiếu
binary, thiếu file báo cáo, và các dependency ảo đều là các điều kiện đã được ghi nhận trong tài liệu:
adapter sẽ ghi nhận chúng và trả về kết quả chứ không bao giờ ném ngoại lệ.
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
from vulnscan.contracts.enums import CWECategory

from .base import AdapterCapability, ScannerAdapter
from .platform import which
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
    """Điểm cơ sở CVSS v3 -> Severity theo contract (None khi không thể xác định)."""
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _name_to_severity(name: str | None) -> Severity | None:
    if not name:
        return None
    return _SEVERITY_BY_NAME.get(name.strip().lower())


def _extract_cwe(vuln: dict[str, Any]) -> CWECategory | None:
    """Lấy ID CWE được hỗ trợ đầu tiên ra khỏi mục lỗ hổng của Dependency-Check."""
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
    """Phân tích báo cáo JSON của Dependency-Check thành các observation + độ bao phủ."""
    now = datetime.now(UTC)
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
                    "virtual dependency: no local artifact to scan" if is_virtual else None
                ),
                extraction_mode=ExtractionMode.DEPENDENCY_GRAPH,
                diagnostics=[f"evidence: {vendor_count} vendor, {product_count} product"],
                unresolved_calls=[],
                cwe_capabilities=[CWECategory.DEPENDENCY_VULNERABILITY],
                cwe_limitations=[],
                analyzed_at=now,
            )
        )

        for vuln in dep.get("vulnerabilities", []) or []:
            vuln_id = str(vuln.get("name") or "unknown")
            description = str(vuln.get("description") or "")
            cvss = vuln.get("cvssv4") or vuln.get("cvssv3") or vuln.get("cvssv2") or {}
            score = cvss.get("baseScore") if isinstance(cvss, dict) else None
            severity = _cvss_to_severity(score) or _name_to_severity(vuln.get("severity"))

            observations.append(
                Observation(
                    observation_id="obs-"
                    + hashlib.sha256(f"{dep_name}|{vuln_id}".encode()).hexdigest()[:16],
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
    """Adapter OWASP Dependency-Check (nhánh dependency)."""

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
            reason=None
            if resolved
            else f"{self.binary_name} not found on PATH; OSV.dev fallback covers manifests",
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        started = datetime.now(UTC)
        tool_cfg = self._tool_config(spec)

        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        cap = self.capabilities()
        if not cap.available:
            # Không có binary ODC (và việc tải NVD không ổn định khi offline): chuyển sang
            # tra cứu OSV.dev trên các manifest thay vì bỏ qua hoàn toàn.
            try:
                from .osv_adapter import OSVAdapter

                return OSVAdapter().run(spec, workdir=workdir)
            except Exception as exc:  # noqa: BLE001 - fallback must never break the scan
                return self._skipped_result(
                    spec, started, f"{cap.unavailable_message()}; osv fallback: {exc}"
                )

        report_path = Path(workdir) / "dependency-check-report.json"
        argv = [
            self.binary_name,
            "--scan",
            workdir,
            "--format",
            "JSON",
            "--out",
            str(report_path.parent),
            "--data",
            str(Path("D:/dev/odc/data")),
            "--kevURL",
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
        ]
        if spec.metadata.get("advisory_cache_ready"):
            argv.append("--noupdate")
        else:
            argv += [
                "--nvdDatafeed",
                "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{0}.json.gz",
            ]
        if tool_cfg:
            for key, value in (tool_cfg.options or {}).items():
                argv += [f"--{key}", str(value)]

        report_path.unlink(missing_ok=True)
        result = self._invoke(argv, cwd=workdir)
        finished = datetime.now(UTC)

        if not result.succeeded or not report_path.exists():
            # ODC thất bại (thiếu NVD DB, không có mạng, không có key): OSV.dev sẽ bao quát
            # các manifest thay vì làm thất bại toàn bộ lượt quét.
            try:
                from .osv_adapter import OSVAdapter

                return OSVAdapter().run(spec, workdir=workdir)
            except Exception as exc:  # noqa: BLE001 - fallback must never break the scan
                return self._fatal(
                    spec, started, finished, result, note=f"dependency-check produced no report; osv fallback: {exc}"
                )

        try:
            report = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            try:
                from .osv_adapter import OSVAdapter

                return OSVAdapter().run(spec, workdir=workdir)
            except Exception as fallback_exc:  # noqa: BLE001 - fallback must never break the scan
                return self._fatal(
                    spec, started, finished, result, note=f"unreadable dependency-check report: {exc}; osv fallback: {fallback_exc}"
                )

        if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
            return self._fatal(
                spec, started, finished, result, note="invalid dependency-check report shape"
            )
        if report.get("scanInfo", {}).get("analysisExceptions"):
            return self._fatal(
                spec,
                started,
                finished,
                result,
                note="dependency-check reported analysis exceptions",
            )

        observations, coverage_records = parse_dependency_check_json(
            report,
            run_id=spec.run_id or "unassigned",
            tool_version=cap.version or "unknown",
            source_snapshot=spec.target_commit_sha,
        )

        skipped = sum(1 for c in coverage_records if c.status == CoverageUnitStatus.SKIPPED)
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
            analyzed_units=len(coverage_records) - skipped,
            skipped_units=skipped,
            failed_units=0,
            errors=[],
            warnings=[],
            duration_ms=result.duration_ms,
            metadata={"advisory_data_sources": report.get("scanInfo", {}).get("dataSource", [])},
        )


__all__ = ["DependencyCheckAdapter", "parse_dependency_check_json"]
