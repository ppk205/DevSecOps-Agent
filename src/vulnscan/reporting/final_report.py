"""Final AI-written vulnerability report (+ deterministic fallback).

The narrative report is the last stage of the pipeline: after scanners,
Laya routing, model review, and independent validation, one bounded model
call turns the *validated* findings into a human-readable report
(txt/md/docx renderings share this single source).

When no provider is configured the stage is skipped and the deterministic
Markdown/HTML/SARIF/JSON renderings remain the report of record — the
baseline never pretends to be AI-written.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

from vulnscan.contracts.finding import Finding
from vulnscan.core.security import sanitize
from vulnscan.providers.budget import BudgetManager
from vulnscan.providers.client import ChatMessage, ProviderClient
from vulnscan.providers.profile_store import load_profile
from vulnscan.reporting.owasp import append_to_narrative, markdown_section

logger = logging.getLogger(__name__)


def _finding_brief(f: Finding, decisions: dict[str, dict[str, Any]]) -> str:
    locs = []
    for o in f.observations[:3]:
        if o.location:
            locs.append(f"{o.location.file_path}:{o.location.line_start} [{o.rule_id}]")
    dec = decisions.get(f.finding_id, {})
    return (
        f"- {f.finding_id} | {f.title} | "
        f"CWE-{f.cwe_category.value if f.cwe_category else 'n/a'} | "
        f"severity={f.severity.value} | status={f.status.value} | "
        f"validator: {(dec.get('rationale', '') or '')[:300]}\n"
        f"  evidence: {'; '.join(locs) or 'no locations'}"
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
    """One-paragraph model-only track summary; ``""`` when nothing to say.

    Counts agreed / model-only / scanner-only (from ``counts``, falling back
    to bucket lengths) plus per-pass candidate counts when the hunt summary
    carries them. Tolerant of missing keys everywhere — never raises.
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
    """Vietnamese model-vs-scanner compare block; empty when no comparison."""
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
    briefs = "\n".join(_finding_brief(f, by_id) for f in findings) or "(no findings)"
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.status.value] = counts.get(f.status.value, 0) + 1
    prompt = (
        "You are a security engineer writing the final vulnerability report "
        "for a scan. Use ONLY the validated findings below — do not invent "
        "vulnerabilities, files, or line numbers. Missing evidence means "
        "'unknown', never 'safe'.\n\n"
        f"Target: {run_metadata.get('target', 'local')} | "
        f"commit: {run_metadata.get('commit', 'n/a')} | "
        f"gate: {run_metadata.get('gate', 'n/a')}\n"
        f"Status counts: {json.dumps(counts)}\n\n"
        f"Validated findings:\n{briefs}\n\n"
        "Write the report in Markdown with exactly these sections:\n"
        "# Tóm tắt điều hành (2-4 câu, tiếng Việt)\n"
        "## Phạm vi & phương pháp (nguồn evidence + Laya route + AI review, 1 đoạn ngắn)\n"
        "## Phát hiện theo mức độ (confirmed trước, mỗi finding: tiêu đề, CWE, "
        + "vị trí file:line, vì sao nguy hiểm, gợi ý khắc phục 1-2 dòng)\n"
        "## Kết luận & bước tiếp theo\n"
        "Keep it factual and bounded: only confirmed/rejected/unresolved "
        "findings listed above."
        " Do not write an OWASP Top 10 section or invent category mappings or counts; "
        "the application appends that section deterministically from normalized CWEs."
    )
    if comparison:
        section = comparison_section(comparison)
        if section:
            prompt = (
                prompt + f"\nModel-vs-scanner comparison (JSON counts + buckets):\n"
                f"{json.dumps(comparison.get('counts', {}))}\n"
                f"{section}\n"
                "Add a '## Đối chiếu model vs scanner' section to the report "
                "covering agreed / model-only / scanner-only items.\n"
            )
        track = model_only_track_paragraph(comparison, run_metadata)
        if track:
            prompt = prompt + f"\nModel-only track summary (one short paragraph):\n{track}\n"
    return prompt


def deterministic_narrative(
    findings: Sequence[Finding],
    decisions: Sequence[dict[str, Any]],
    run_metadata: dict[str, Any],
    *,
    comparison: dict[str, Any] | None = None,
) -> str:
    """Template fallback used when no provider is configured."""
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
    """One bounded model call → narrative Markdown. Never raises."""
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
            report["markdown"] = append_to_narrative(resp.content, findings)
            report["status"] = "completed"
            reported_tokens = resp.usage.get("total_tokens")
            report["detail"] = (
                f"{reported_tokens} reported tokens"
                if type(reported_tokens) is int
                else "Token count unavailable"
            )
        else:
            # Empty model reply: keep a deterministic narrative so the
            # report file is never 0 bytes; mark partial, not failed.
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
