"""Semgrep adapter — deterministic source-code scanner.

Handles both the legacy ``sarif`` path (Semgrep 1.x ``--json``) and the
newer SARIF-v2 output.  Parsing is pure; the ``run`` method shells out
via ``_invoke`` so that tests can inject fixture output.

Missing-binary handling: ``capabilities`` returns an unavailable record
when ``semgrep`` is not on PATH; ``run`` then returns a ``skipped`` or
``failed`` envelope without raising.
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
)

from .base import AdapterCapability, ScannerAdapter
from .mapping import cwe_category
from .platform import which
from .tool_versions import probe_version

# --- severity map --------------------------------------------------------- #

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "INVENTORY": Severity.INFO,
    "UNDETERMINED": Severity.UNDETERMINED,
    # Semgrep numeric-like
    "1": Severity.HIGH,
    "2": Severity.MEDIUM,
    "3": Severity.LOW,
    "4": Severity.INFO,
    "5": Severity.INFO,
}


def _map_severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get(raw.upper().strip(), Severity.UNDETERMINED)


def _make_observation_id(rule_id: str, file_path: str, line: int) -> str:
    """Deterministic observation ID so repeated parses merge cleanly."""
    blob = f"{rule_id}|{file_path}|{line}"
    return "obs-" + hashlib.sha1(blob.encode()).hexdigest()[:16]


# --- SARIF helpers ------------------------------------------------------- #


def _extract_from_sarif_v2(
    sarif: dict[str, Any],
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse a SARIF v2 document (Semgrep ``--sarif``)."""
    now = datetime.now(UTC)
    observations: list[Observation] = []
    coverage: list[CoverageRecord] = []

    for run in sarif.get("runs", []):
        tool_info = run.get("tool", {}).get("driver", {})
        _rules = {r["id"]: r for r in tool_info.get("rules", [])}
        rule_ver = tool_info.get("semanticVersion", tool_version)

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "warning")
            message = result.get("message", {}).get("text", "")
            locations = result.get("locations", [])
            if not locations:
                continue
            phys = locations[0].get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            file_path = art.get("uri", "")
            region = phys.get("region", {})
            line_start = region.get("startLine", 1)
            line_end = region.get("endLine")
            col_start = region.get("startColumn")
            col_end = region.get("endColumn")

            # CWE extraction. Semgrep tags are formatted as
            # "CWE-89: Improper ...", so the label must be split from its
            # description before it can be matched against the enum.
            cwe_cat = None
            for tag in _rules.get(rule_id, {}).get("properties", {}).get("tags", []):
                if isinstance(tag, str) and tag.strip().upper().startswith("CWE-"):
                    cwe_cat = cwe_category(tag.split(":", 1)[0])
                    if cwe_cat is not None:
                        break

            # Determine language
            ext = Path(file_path).suffix.lower()
            lang = (
                LanguageKind.JAVA
                if ext == ".java"
                else (LanguageKind.JSP if ext in (".jsp", ".jspx") else LanguageKind.OTHER)
            )

            observations.append(
                Observation(
                    run_id=run_id,
                    tool=ToolName.SEMGREP,
                    tool_version=rule_ver,
                    rule_id=rule_id,
                    cwe_category=cwe_cat,
                    severity=_map_severity(level),
                    native_severity=level,
                    message=message[:1000],
                    location=SourceCoordinate(
                        file_path=file_path,
                        language=lang,
                        line_start=line_start,
                        line_end=line_end if line_end else line_start,
                        column_start=col_start,
                        column_end=col_end,
                    ),
                    detected_at=now,
                    metadata={"sarif_rule_index": result.get("ruleIndex")},
                    observation_id=_make_observation_id(rule_id, file_path, line_start),
                )
            )

        # Coverage from SARIF invocations
        for invocation in run.get("invocations", []):
            art_locs = invocation.get("artifacts", [])
            for al in art_locs:
                uri = al.get("location", {}).get("artifactLocation", {}).get("uri", "")
                ext = Path(uri).suffix.lower()
                lang = (
                    LanguageKind.JAVA
                    if ext == ".java"
                    else (LanguageKind.JSP if ext in (".jsp", ".jspx") else LanguageKind.OTHER)
                )
                coverage.append(
                    CoverageRecord(
                        run_id=run_id,
                        tool=ToolName.SEMGREP,
                        tool_version=rule_ver,
                        source_snapshot=source_snapshot,
                        unit_path=uri,
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


def _extract_from_legacy_json(
    data: dict[str, Any],
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse Semgrep legacy ``--json`` output (list of ``results``)."""
    now = datetime.now(UTC)
    observations: list[Observation] = []
    coverage: list[CoverageRecord] = []

    for res in data.get("results", []):
        rule_id = res.get("check_id", "unknown")
        severity_raw = res.get("extra", {}).get("severity", "WARNING")
        message = res.get("extra", {}).get("message", "")
        path = res.get("path", "")
        start_line = res.get("start", {}).get("line", 1)
        end_line = res.get("end", {}).get("line")
        start_col = res.get("start", {}).get("col")
        end_col = res.get("end", {}).get("col")

        ext = Path(path).suffix.lower()
        lang = (
            LanguageKind.JAVA
            if ext == ".java"
            else (LanguageKind.JSP if ext in (".jsp", ".jspx") else LanguageKind.OTHER)
        )

        # CWE extraction. The legacy ``--json`` schema puts CWE labels under
        # ``extra.metadata.cwe`` as a list of "CWE-89: description" strings;
        # there is no ``tags`` key in this format, so reading only ``tags``
        # silently classified every finding as UNCLASSIFIED.
        cwe_cat = None
        metadata = res.get("extra", {}).get("metadata", {})
        labels = list(metadata.get("cwe", []))
        labels += [t for t in metadata.get("tags", []) if isinstance(t, str)]
        for label in labels:
            if isinstance(label, str) and label.strip().upper().startswith("CWE-"):
                cwe_cat = cwe_category(label.split(":", 1)[0])
                if cwe_cat is not None:
                    break

        observations.append(
            Observation(
                run_id=run_id,
                tool=ToolName.SEMGREP,
                tool_version=tool_version,
                rule_id=rule_id,
                cwe_category=cwe_cat,
                severity=_map_severity(severity_raw),
                native_severity=severity_raw,
                message=message[:1000],
                location=SourceCoordinate(
                    file_path=path,
                    language=lang,
                    line_start=start_line,
                    line_end=end_line if end_line else start_line,
                    column_start=start_col,
                    column_end=end_col,
                ),
                detected_at=now,
                metadata={"code_excerpt": str(res.get("extra", {}).get("lines", ""))},
                observation_id=_make_observation_id(rule_id, path, start_line),
            )
        )

    # Coverage from the ``scan_targets`` list
    for target in data.get("paths", {}).get("scanned", data.get("scan_info", {}).get("files", [])):
        ext = Path(target).suffix.lower()
        lang = (
            LanguageKind.JAVA
            if ext == ".java"
            else (LanguageKind.JSP if ext in (".jsp", ".jspx") else LanguageKind.OTHER)
        )
        coverage.append(
            CoverageRecord(
                run_id=run_id,
                tool=ToolName.SEMGREP,
                tool_version=tool_version,
                source_snapshot=source_snapshot,
                unit_path=target,
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


def parse_sarif(
    text: str,
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse Semgrep SARIF text into Observations and CoverageRecords."""
    sarif = json.loads(text)
    return _extract_from_sarif_v2(
        sarif, run_id=run_id, tool_version=tool_version, source_snapshot=source_snapshot
    )


def parse_json(
    text: str,
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Parse Semgrep legacy JSON text into Observations and CoverageRecords."""
    data = json.loads(text)
    return _extract_from_legacy_json(
        data, run_id=run_id, tool_version=tool_version, source_snapshot=source_snapshot
    )


class SemgrepAdapter(ScannerAdapter):
    """Deterministic Semgrep adapter with SARIF + legacy JSON paths."""

    tool = ToolName.SEMGREP
    binary_name = "semgrep"

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
        cap = self.capabilities()
        from datetime import datetime

        started = datetime.now(UTC)
        tool_cfg = self._tool_config(spec)

        # Disabled in spec?
        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        # Missing binary?
        if not cap.available:
            return self._skipped_result(spec, started, cap.unavailable_message())

        # Build argv
        argv: list[str] = [self.binary_name]
        argv += ["--metrics", "off", "--disable-version-check"]
        if not (tool_cfg and tool_cfg.rule_paths):
            argv += ["--config", str(Path(__file__).with_name("rules") / "java.yml")]
        argv += ["--json"]
        argv += ["--no-git-ignore"]
        if tool_cfg and tool_cfg.rule_paths:
            for rp in tool_cfg.rule_paths:
                argv += ["--config", rp]
        if tool_cfg:
            for k, v in (tool_cfg.options or {}).items():
                if k == "severity":
                    argv += ["--severity", str(v)]
                elif k == "max_target_bytes":
                    argv += ["--max-target-bytes", str(v)]
                elif k == "jobs":
                    argv += ["--jobs", str(v)]
                # other unknown options are skipped
        argv += ["."]

        result = self._invoke(argv, cwd=workdir)
        finished = datetime.now(UTC)

        if not result.succeeded:
            if result.timed_out or result.returncode not in (0, 1):
                return self._fatal(spec, started, finished, result, note="semgrep failed")
            # returncode == 1 means findings (not a failure)
            # fall through to parse stdout
            if not result.stdout.strip():
                return self._fatal(
                    spec, started, finished, result, note="semgrep produced no output"
                )

        raw_text = result.stdout.strip()
        if not raw_text:
            return self._fatal(spec, started, finished, result, note="semgrep produced no output")

        # Detect format: SARIF starts with `{ "runs"`, legacy JSON has `"results"`
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            return self._fatal(
                spec, started, finished, result, note="semgrep output is not valid JSON"
            )

        if not isinstance(data, dict) or not ({"results", "runs"} & data.keys()):
            return self._fatal(spec, started, finished, result, note="invalid Semgrep report shape")
        if "runs" in data:
            observations, coverage_records = parse_sarif(
                raw_text,
                run_id=spec.run_id or "unassigned",
                tool_version=cap.version or "unknown",
                source_snapshot=spec.target_commit_sha,
            )
        else:
            observations, coverage_records = parse_json(
                raw_text,
                run_id=spec.run_id or "unassigned",
                tool_version=cap.version or "unknown",
                source_snapshot=spec.target_commit_sha,
            )

        if not isinstance(data, dict) or not ({"results", "runs"} & data.keys()):
            return self._fatal(spec, started, finished, result, note="invalid Semgrep report shape")
        if not (tool_cfg and tool_cfg.rule_paths):
            for record in coverage_records:
                record.cwe_capabilities = [
                    CWECategory("CWE-89"),
                    CWECategory("CWE-78"),
                    CWECategory("CWE-327"),
                ]
                record.metadata["rules_pack_version"] = "0.2.0"
        for path in Path(workdir).rglob("*.jsp"):
            coverage_records.append(
                CoverageRecord(
                    run_id=spec.run_id or "unassigned",
                    tool=self.tool,
                    tool_version=cap.version or "unknown",
                    source_snapshot=spec.target_commit_sha,
                    unit_path=path.relative_to(workdir).as_posix(),
                    unit_language=LanguageKind.JSP,
                    eligible=True,
                    status=CoverageUnitStatus.UNSUPPORTED,
                    limitation_reason="Versioned Java rules do not parse JSP",
                    analyzed_at=finished,
                )
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
            coverage_records=coverage_records,
            raw_output_refs=[],
            eligible_units=len(coverage_records),
            analyzed_units=sum(
                1 for c in coverage_records if c.status == CoverageUnitStatus.ANALYZED
            ),
            skipped_units=0,
            failed_units=0,
            errors=[str(e.get("message", "Semgrep error")) for e in data.get("errors", [])],
            warnings=[],
            duration_ms=result.duration_ms,
            metadata={"source_format": "sarif" if "runs" in data else "json"},
        )


__all__ = ["SemgrepAdapter", "parse_json", "parse_sarif"]
