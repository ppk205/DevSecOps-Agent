"""Semgrep adapter — công cụ quét mã nguồn tất định.

Xử lý cả đường dẫn ``sarif`` cũ (Semgrep 1.x ``--json``) lẫn output
SARIF-v2 mới hơn. Quá trình parse là hàm thuần túy (pure); phương thức ``run`` gọi shell
qua ``_invoke`` để các bài test có thể inject output fixture.

Xử lý khi thiếu binary: ``capabilities`` trả về bản ghi unavailable
khi ``semgrep`` không có trong PATH; ``run`` sau đó trả về phong bì ``skipped`` hoặc
``failed`` mà không ném ngoại lệ.
"""

from __future__ import annotations

import hashlib
import json
import re
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
from .mapping import cwe_category
from .platform import which
from .tool_versions import probe_version

# --- bảng ánh xạ severity ------------------------------------------------- #

_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "INVENTORY": Severity.INFO,
    "UNDETERMINED": Severity.UNDETERMINED,
    # Dạng số của Semgrep
    "1": Severity.HIGH,
    "2": Severity.MEDIUM,
    "3": Severity.LOW,
    "4": Severity.INFO,
    "5": Severity.INFO,
}


def _map_severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get(raw.upper().strip(), Severity.UNDETERMINED)


# The bundled rule packs have no rules for these languages.
_NO_RULE_LANGUAGES = frozenset(
    {LanguageKind.GO, LanguageKind.RUBY, LanguageKind.CPP, LanguageKind.CSHARP}
)

_TIMEOUT_RE = re.compile(r"Timeout when running \S+ on (\S+?)(?::\s*$|\s*$)")


def partition_semgrep_errors(messages: list[str], stderr: str = "") -> tuple[list[str], set[str]]:
    """Tách các lỗi của semgrep thành lỗi nghiêm trọng (hard failure) và ghi chú coverage do timeout rule.

    Timeout (một rule bỏ cuộc trên một file quá lớn) là các giới hạn
    coverage được ghi nhận theo từng đơn vị, không bao giờ là lỗi thất bại của lần chạy. Hàm thuần túy.
    """
    timed_out: set[str] = set()
    for line in (stderr or "").splitlines():
        m = _TIMEOUT_RE.search(line)
        if m:
            timed_out.add(m.group(1).replace("\\", "/"))
    for message in messages:
        m = _TIMEOUT_RE.search(message)
        if m:
            timed_out.add(m.group(1).replace("\\", "/"))
    hard = [m for m in messages if not _TIMEOUT_RE.search(m)]
    return hard, timed_out


def _make_observation_id(rule_id: str, file_path: str, line: int) -> str:
    """ID observation tất định để các lần parse lặp lại hợp nhất sạch sẽ."""
    blob = f"{rule_id}|{file_path}|{line}"
    return "obs-" + hashlib.sha1(blob.encode()).hexdigest()[:16]


# --- Các helper SARIF ----------------------------------------------------- #


def _extract_from_sarif_v2(
    sarif: dict[str, Any],
    *,
    run_id: str,
    tool_version: str,
    source_snapshot: str,
) -> tuple[list[Observation], list[CoverageRecord]]:
    """Phân tích tài liệu SARIF v2 (Semgrep ``--sarif``)."""
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

            # Trích xuất CWE. Các tag của Semgrep được định dạng là
            # "CWE-89: Improper ...", nên nhãn phải được tách khỏi phần
            # mô tả của nó trước khi có thể so khớp với enum.
            cwe_cat = None
            for tag in _rules.get(rule_id, {}).get("properties", {}).get("tags", []):
                if isinstance(tag, str) and tag.strip().upper().startswith("CWE-"):
                    cwe_cat = cwe_category(tag.split(":", 1)[0])
                    if cwe_cat is not None:
                        break

            # Xác định ngôn ngữ
            lang = language_from_extension(file_path)

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

        # Coverage từ các lượt gọi SARIF
        for invocation in run.get("invocations", []):
            art_locs = invocation.get("artifacts", [])
            for al in art_locs:
                uri = al.get("location", {}).get("artifactLocation", {}).get("uri", "")
                lang = language_from_extension(uri)
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
    """Phân tích output ``--json`` cũ của Semgrep (danh sách ``results``)."""
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

        lang = language_from_extension(path)

        # Trích xuất CWE. Schema ``--json`` cũ đặt các nhãn CWE dưới
        # ``extra.metadata.cwe`` dưới dạng danh sách chuỗi "CWE-89: description";
        # không có khóa ``tags`` trong định dạng này, nên việc chỉ đọc ``tags``
        # sẽ âm thầm phân loại mọi finding thành UNCLASSIFIED.
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

    # Coverage từ danh sách ``scan_targets```
    for target in data.get("paths", {}).get("scanned", data.get("scan_info", {}).get("files", [])):
        lang = language_from_extension(target)
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
    """Phân tích văn bản SARIF của Semgrep thành các Observation và CoverageRecord."""
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
    """Phân tích văn bản JSON cũ của Semgrep thành các Observation và CoverageRecord."""
    data = json.loads(text)
    return _extract_from_legacy_json(
        data, run_id=run_id, tool_version=tool_version, source_snapshot=source_snapshot
    )


class SemgrepAdapter(ScannerAdapter):
    """Semgrep adapter tất định với các đường dẫn SARIF + JSON cũ."""

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

        # Bị vô hiệu hóa trong spec?
        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "disabled in scan spec")

        # Thiếu binary?
        if not cap.available:
            return self._skipped_result(spec, started, cap.unavailable_message())

        # Xây dựng argv
        argv: list[str] = [self.binary_name]
        argv += ["--metrics", "off", "--disable-version-check"]
        if not (tool_cfg and tool_cfg.rule_paths):
            rules_dir = Path(__file__).with_name("rules")
            for rules_file in sorted(rules_dir.glob("*.yml")):
                argv += ["--config", str(rules_file)]
        argv += ["--json"]
        argv += ["--no-git-ignore"]
        # Output bản build được sao chép vào snapshot (target/classes, jars) không phải là
        # source: ngăn semgrep quét hoặc các file .js lớn của bên thứ ba sẽ làm timeout rule.
        argv += ["--exclude", "target"]
        # Các bundle đã nén gọn không bao giờ quét mẫu hiệu quả (một dòng
        # 400KB đơn lẻ như ace.js làm timeout các rule taint trên toàn file); loại trừ
        # ngay từ đầu. Bước hoàn tất vẫn ghi nhận từng file là unsupported kèm lý do.
        argv += ["--exclude", "*.min.js"]
        if tool_cfg and tool_cfg.rule_paths:
            for rp in tool_cfg.rule_paths:
                argv += ["--config", rp]
        target = "."
        if tool_cfg:
            for k, v in (tool_cfg.options or {}).items():
                if k == "severity":
                    argv += ["--severity", str(v)]
                elif k == "max_target_bytes":
                    argv += ["--max-target-bytes", str(v)]
                elif k == "jobs":
                    argv += ["--jobs", str(v)]
                elif k == "target_path" and isinstance(v, str) and v.strip():
                    target = v.strip()
                # other unknown options are skipped
        argv += [target]

        result = self._invoke(argv, cwd=workdir)
        finished = datetime.now(UTC)

        if not result.succeeded:
            if result.timed_out or result.returncode not in (0, 1):
                return self._fatal(spec, started, finished, result, note="semgrep failed")
            # returncode == 1 nghĩa là có finding (không phải lỗi thực thi)
            # chuyển tiếp để phân tích stdout
            if not result.stdout.strip():
                return self._fatal(
                    spec, started, finished, result, note="semgrep produced no output"
                )

        raw_text = result.stdout.strip()
        if not raw_text:
            return self._fatal(spec, started, finished, result, note="semgrep produced no output")

        # Nhận diện định dạng: SARIF bắt đầu bằng `{ "runs"`, JSON cũ có `"results"`
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
        # Hoàn tất: semgrep quét mọi target được cung cấp, do đó một file trong
        # inventory không có bản ghi và không có bằng chứng stderr nghĩa là đã quét sạch — đánh dấu
        # là analyzed. Các file mà semgrep chứng minh đã bỏ qua (timeout rule,
        # bundle đã nén gọn) sẽ nhận bản ghi unsupported kèm lý do thay vì
        # biến mất thành các lỗi giả "missing coverage".
        # Timeout rule xuất hiện cả ở stderr và dưới dạng lỗi JSON; cả hai đều là
        # giới hạn coverage, không bao giờ là lỗi thất bại của lần chạy.
        semgrep_errors = [str(e.get("message", "Semgrep error")) for e in data.get("errors", [])]
        hard_errors, timed_out = partition_semgrep_errors(semgrep_errors, result.stderr or "")

        scanned = {c.unit_path.replace("\\", "/") for c in coverage_records}
        manifest = (spec.metadata or {}).get("manifest") or {}
        for name in manifest.get("inventory", []) or []:
            norm = name.replace("\\", "/")
            if norm in scanned or language_from_extension(norm) is None:
                continue
            timed = any(t == norm or norm.endswith(t.lstrip("/")) for t in timed_out)
            minified = norm.endswith(".min.js")
            no_rules = language_from_extension(norm) in _NO_RULE_LANGUAGES
            if timed or minified or no_rules:
                coverage_records.append(
                    CoverageRecord(
                        run_id=spec.run_id or "unassigned",
                        tool=self.tool,
                        tool_version=cap.version or "unknown",
                        source_snapshot=spec.target_commit_sha,
                        unit_path=norm,
                        unit_language=language_from_extension(norm),
                        eligible=True,
                        status=CoverageUnitStatus.UNSUPPORTED,
                        limitation_reason=(
                            "no Semgrep rules ran for this language"
                            if no_rules
                            else "rule timeout on oversized/minified file"
                            if timed
                            else "minified bundle: pattern scan skipped"
                        ),
                        analyzed_at=finished,
                    )
                )
            else:
                coverage_records.append(
                    CoverageRecord(
                        run_id=spec.run_id or "unassigned",
                        tool=self.tool,
                        tool_version=cap.version or "unknown",
                        source_snapshot=spec.target_commit_sha,
                        unit_path=norm,
                        unit_language=language_from_extension(norm),
                        eligible=True,
                        status=CoverageUnitStatus.ANALYZED,
                        extraction_mode=ExtractionMode.PATTERN,
                        diagnostics=[],
                        unresolved_calls=[],
                        cwe_capabilities=[],
                        cwe_limitations=[],
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
            errors=hard_errors,
            warnings=[],
            duration_ms=result.duration_ms,
            metadata={"source_format": "sarif" if "runs" in data else "json"},
        )


__all__ = ["SemgrepAdapter", "parse_json", "parse_sarif"]
