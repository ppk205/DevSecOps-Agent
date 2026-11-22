"""Báo cáo lỗ hổng cuối cùng do AI viết (+ dự phòng tất định).

Báo cáo diễn giải là giai đoạn cuối của pipeline: sau các scanner,
định tuyến Laya, đánh giá của model, và xác thực độc lập, một lượt gọi
model có giới hạn sẽ chuyển các finding *đã xác thực* thành báo cáo cho con người đọc
(các bản render txt/md/docx đều dùng chung nguồn duy nhất này).

Khi không có provider nào được cấu hình, giai đoạn này sẽ được bỏ qua và các bản
render tất định Markdown/HTML/SARIF/JSON vẫn là báo cáo chuẩn — baseline
không bao giờ giả vờ là do AI viết.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

from vulnscan.contracts.enums import FindingStatus, Severity
from vulnscan.contracts.finding import Finding
from vulnscan.core.security import sanitize
from vulnscan.providers.budget import BudgetManager
from vulnscan.providers.client import ChatMessage, ProviderClient
from vulnscan.providers.profile_store import load_profile
from vulnscan.reporting.owasp import append_to_narrative, markdown_section

logger = logging.getLogger(__name__)


_REPORT_PROMPT_MAX_CHARS = 6000
_REPORT_SAMPLE_LIMIT = 12
_SEVERITY_ORDER = {severity: index for index, severity in enumerate(Severity)}


def _finding_brief(f: Finding, decisions: dict[str, dict[str, Any]]) -> str:
    location = next((o.location for o in f.observations if o.location), None)
    where = (
        f"{location.file_path}:{location.line_start}"
        if location and len(location.file_path) <= 240
        else "unknown"
    )
    rationale = str(decisions.get(f.finding_id, {}).get("rationale") or "")[:160]
    return (
        f"- {f.finding_id[:80]} | {f.title[:160]} | "
        f"{f.cwe_category.value if f.cwe_category else 'unclassified'} | "
        f"{f.severity.value}/{f.status.value} | {where}"
        + (f" | validator: {rationale}" if rationale else "")
    )


def _candidate_line(item: Any) -> str:
    if isinstance(item, dict):
        return f"{item.get('file', '?')}:{item.get('line', '?')}"
    return "?"


def _finding_line(item: Any) -> str:
    if isinstance(item, dict):
        obs = (item.get("observations") or [{}])[0] if item.get("observations") else {}
        loc = obs.get("location", {}) if isinstance(obs, dict) else {}
        return f"{loc.get('file_path', '?')}:{loc.get('line_start', '?')}"
    locs = [o.location for o in getattr(item, "observations", [])[:1] if o.location]
    if locs:
        return f"{locs[0].file_path}:{locs[0].line_start}"
    return "?"


def _finding_title(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("title", item.get("finding_id", "?")))
    return str(getattr(item, "title", getattr(item, "finding_id", "?")))


def model_only_track_paragraph(
    comparison: dict[str, Any] | None,
    run_metadata: dict[str, Any] | None = None,
) -> str:
    """Tóm tắt một đoạn về nhánh chỉ có model; trả về ``""`` khi không có gì để thông báo.

    Đếm các finding agreed / model-only / scanner-only (từ ``counts``, dự phòng
    bằng độ dài bucket) cộng với số lượng ứng viên theo từng lượt khi phần tóm tắt hunt
    có chứa chúng. Chấp nhận các khóa bị thiếu ở mọi nơi — không bao giờ ném ngoại lệ.
    """
    comp = comparison if isinstance(comparison, dict) else {}
    meta = run_metadata if isinstance(run_metadata, dict) else {}
    raw_counts = comp.get("counts")
    counts = raw_counts if isinstance(raw_counts, dict) else {}

    def _num(key: str, bucket: Any) -> int:
        try:
            n = int(counts.get(key, 0) or 0)
        except (TypeError, ValueError):
            n = 0
        if n:
            return n
        return len(bucket) if isinstance(bucket, list) else 0

    agreed = _num("agreed", comp.get("agreed"))
    model_only = _num("model_only", comp.get("model_only"))
    scanner_only = _num("scanner_only", comp.get("scanner_only"))
    if not (agreed or model_only or scanner_only):
        return ""

    passes: Any = comp.get("passes")
    if not isinstance(passes, list):
        passes = None
        for key in ("passes", "hunt_passes", "hunt_summary", "hunt"):
            value = meta.get(key)
            if isinstance(value, list):
                passes = value
                break
            if isinstance(value, dict) and isinstance(value.get("passes"), list):
                passes = value["passes"]
                break
    bits: list[str] = []
    if isinstance(passes, list):
        for entry in passes:
            if not isinstance(entry, dict):
                continue
            family = str(entry.get("family", "?"))
            try:
                n = int(entry.get("candidates", entry.get("count", 0)) or 0)
            except (TypeError, ValueError):
                n = 0
            bits.append(f"{family}:{n}")
    text = (
        f"Luồng model-only: nhất trí {agreed}, chỉ model thấy {model_only} "
        f"(chờ người xem lại trong hunt.json, chưa thành finding chính thức "
        f"khi thiếu evidence), chỉ scanner thấy {scanner_only}."
    )
    if bits:
        text += " Theo pass: " + ", ".join(bits) + "."
    return text


def comparison_section(comparison: dict[str, Any] | None) -> str:
    """Khối so sánh model và scanner bằng tiếng Việt; rỗng khi không có so sánh."""
    if not comparison:
        return ""
    counts = comparison.get("counts", {}) or {}
    if not any(counts.get(k, 0) for k in ("agreed", "model_only", "scanner_only")):
        return ""
    lines = ["## Đối chiếu model vs scanner", ""]
    agreed = comparison.get("agreed", []) or []
    lines.append(f"- Nhất trí (cả model và scanner đều thấy): {len(agreed)}")
    for pair in agreed:
        cand = pair.get("candidate", {}) if isinstance(pair, dict) else {}
        title = cand.get("title", "?") if isinstance(cand, dict) else "?"
        lines.append(f"  - {title} @ {_candidate_line(cand)}")
    model_only = comparison.get("model_only", []) or []
    lines.append(f"- Chỉ model thấy (scanner bỏ sót, cần người xem lại): {len(model_only)}")
    for item in model_only:
        title = item.get("title", "?") if isinstance(item, dict) else _finding_title(item)
        lines.append(f"  - {title} @ {_candidate_line(item)}")
    scanner_only = comparison.get("scanner_only", []) or []
    lines.append(f"- Chỉ scanner thấy (model không liệt kê): {len(scanner_only)}")
    for item in scanner_only:
        lines.append(f"  - {_finding_title(item)} @ {_finding_line(item)}")
    lines.append("")
    return "\n".join(lines)


def build_report_prompt(
    findings: Sequence[Finding],
    decisions: Sequence[dict[str, Any]],
    run_metadata: dict[str, Any],
    *,
    comparison: dict[str, Any] | None = None,
) -> str:
    by_id = {str(d.get("finding_id")): d for d in decisions}
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.status.value] = counts.get(finding.status.value, 0) + 1
    header = (
        "Summarize this scan in Vietnamese Markdown. Use only the supplied facts. "
        "Missing evidence is unknown. Preserve finding statuses and exact locations. "
        "Use four sections: Tóm tắt điều hành, Phạm vi và phương pháp, "
        "Phát hiện ưu tiên, Kết luận và bước tiếp theo. "
        "Comparison and OWASP details are rendered by the application.\n\n"
        f"Target: {str(run_metadata.get('target', 'local'))[:240]} | "
        f"commit: {str(run_metadata.get('commit', 'n/a'))[:80]} | "
        f"gate: {str(run_metadata.get('gate', 'n/a'))[:40]}\n"
        f"Status counts: {json.dumps(counts)}\n"
    )
    if comparison and isinstance(comparison.get("counts"), dict):
        totals = {
            key: value
            for key in ("agreed", "model_only", "scanner_only")
            if type(value := comparison["counts"].get(key)) is int
        }
        if totals:
            header += f"## Đối chiếu model vs scanner: {json.dumps(totals)}\n"

    ordered = sorted(
        findings,
        key=lambda f: (f.status != FindingStatus.CONFIRMED, _SEVERITY_ORDER[f.severity]),
    )
    lines: list[str] = []
    used = len(header) + 200  # Reserve space for the sample heading and omission notice.
    for finding in ordered[:_REPORT_SAMPLE_LIMIT]:
        line = _finding_brief(finding, by_id)
        if used + len(line) + 1 > _REPORT_PROMPT_MAX_CHARS:
            break
        lines.append(line)
        used += len(line) + 1
    sample = "\n".join(lines) or "(no findings)"
    omitted = len(findings) - len(lines)
    return (
        f"{header}\nFinding samples ({len(lines)} of {len(findings)}):\n{sample}\n"
        f"{omitted} omitted from the model input. Full details are in the scan exports."
    )


def deterministic_narrative(
    findings: Sequence[Finding],
    decisions: Sequence[dict[str, Any]],
    run_metadata: dict[str, Any],
    *,
    comparison: dict[str, Any] | None = None,
) -> str:
    """Template dự phòng được sử dụng khi không có provider nào được cấu hình."""
    by_id = {str(d.get("finding_id")): d for d in decisions}
    lines = [
        "# Báo cáo lỗ hổng (tổng hợp từ evidence, chưa qua AI)",
        "",
        (
            f"Mục tiêu: {run_metadata.get('target', 'local')} | "
            f"commit: {run_metadata.get('commit', 'n/a')} | "
            f"gate: {run_metadata.get('gate', 'n/a')}"
        ),
        "",
    ]
    section = comparison_section(comparison)
    if section:
        lines.extend([section, ""])
    track = model_only_track_paragraph(comparison, run_metadata)
    if track:
        lines.extend([track, ""])
    for f in findings:
        dec = by_id.get(f.finding_id, {})
        lines.append(f"## {f.title} [{f.status.value}]")
        lines.append(
            f"{f.cwe_category.value if f.cwe_category else 'Unclassified'} | severity={f.severity.value}"
        )
        for o in f.observations[:5]:
            if o.location:
                lines.append(f"- {o.location.file_path}:{o.location.line_start} [{o.rule_id}]")
        if dec.get("rationale"):
            lines.append(f"Validator: {dec['rationale']}")
        lines.append("")
    return str(sanitize("\n".join(lines))).rstrip() + "\n\n" + markdown_section(findings) + "\n"


def run_final_report(
    findings: Sequence[Finding],
    decisions: Sequence[dict[str, Any]],
    run_metadata: dict[str, Any],
    *,
    profile_id: str | None,
    model: str | None = None,
    budget: BudgetManager | None = None,
    comparison: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Một lượt gọi model có giới hạn → Markdown diễn giải. Không bao giờ ném ngoại lệ."""
    report: dict[str, Any] = {
        "stage": "final_report",
        "status": "skipped",
        "detail": "",
        "model": model or "",
        "provider": profile_id or "",
        "markdown": "",
        "ai_written": False,
    }
    if not profile_id:
        report["detail"] = "no provider profile configured"
        report["markdown"] = deterministic_narrative(
            findings, decisions, run_metadata, comparison=comparison
        )
        return report
    try:
        profile = load_profile(profile_id)
        client = ProviderClient(profile, budget or BudgetManager())
        prompt = build_report_prompt(findings, decisions, run_metadata, comparison=comparison)
        resp = client.chat(
            [ChatMessage(role="user", content=prompt)],
            model=model or profile.default_model,
            max_tokens=4000,
        )
        report["markdown"] = resp.content
        report["model"] = resp.model
        report["provider"] = profile.id
        report["ai_written"] = True
        if resp.content.strip():
            comparison_text = comparison_section(comparison)
            track = model_only_track_paragraph(comparison, run_metadata)
            narrative = "\n\n".join(
                part.strip() for part in (resp.content, comparison_text, track) if part.strip()
            )
            report["markdown"] = append_to_narrative(str(sanitize(narrative)), findings)
            report["status"] = "completed"
            reported_tokens = resp.usage.get("total_tokens")
            report["detail"] = (
                f"{reported_tokens} reported tokens"
                if type(reported_tokens) is int
                else "Token count unavailable"
            )
        else:
            # Phản hồi của model rỗng: duy trì phần diễn giải tất định để
            # file báo cáo không bao giờ có kích thước 0 byte; đánh dấu partial chứ không phải failed.
            report["markdown"] = deterministic_narrative(
                findings, decisions, run_metadata, comparison=comparison
            )
            report["ai_written"] = False
            report["status"] = "partial"
            report["detail"] = "empty reply — deterministic narrative used"
    except Exception as exc:  # noqa: BLE001 — report stage never fails a run
        logger.warning("final report failed: %s", exc)
        report["status"] = "failed"
        report["detail"] = f"{type(exc).__name__}"
        report["markdown"] = deterministic_narrative(
            findings, decisions, run_metadata, comparison=comparison
        )
    return report
