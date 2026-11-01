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
from vulnscan.providers.budget import BudgetManager
from vulnscan.providers.client import ChatMessage, ProviderClient
from vulnscan.providers.profile_store import load_profile

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


def build_report_prompt(
    findings: Sequence[Finding],
    decisions: Sequence[dict[str, Any]],
    run_metadata: dict[str, Any],
) -> str:
    by_id = {str(d.get("finding_id")): d for d in decisions}
    briefs = "\n".join(_finding_brief(f, by_id) for f in findings) or "(no findings)"
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.status.value] = counts.get(f.status.value, 0) + 1
    return (
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
    )


def deterministic_narrative(
    findings: Sequence[Finding],
    decisions: Sequence[dict[str, Any]],
    run_metadata: dict[str, Any],
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
    for f in findings:
        dec = by_id.get(f.finding_id, {})
        lines.append(f"## {f.title} [{f.status.value}]")
        lines.append(
            f"CWE-{f.cwe_category.value if f.cwe_category else 'n/a'} | severity={f.severity.value}"
        )
        for o in f.observations[:5]:
            if o.location:
                lines.append(f"- {o.location.file_path}:{o.location.line_start} [{o.rule_id}]")
        if dec.get("rationale"):
            lines.append(f"Validator: {dec['rationale']}")
        lines.append("")
    return "\n".join(lines)


def run_final_report(
    findings: Sequence[Finding],
    decisions: Sequence[dict[str, Any]],
    run_metadata: dict[str, Any],
    *,
    profile_id: str | None,
    model: str | None = None,
    budget: BudgetManager | None = None,
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
        report["markdown"] = deterministic_narrative(findings, decisions, run_metadata)
        return report
    try:
        profile = load_profile(profile_id)
        client = ProviderClient(profile, budget or BudgetManager())
        prompt = build_report_prompt(findings, decisions, run_metadata)
        resp = client.chat(
            [ChatMessage(role="user", content=prompt)],
            model=model or profile.default_model,
            max_tokens=4000,
        )
        report["markdown"] = resp.content
        report["model"] = resp.model
        report["provider"] = profile.id
        report["ai_written"] = True
        report["status"] = "completed" if resp.content.strip() else "failed"
        report["detail"] = (
            f"{resp.usage.get('total_tokens', 0)} tokens" if resp.content.strip() else "empty reply"
        )
    except Exception as exc:  # noqa: BLE001 — report stage never fails a run
        logger.warning("final report failed: %s", exc)
        report["status"] = "failed"
        report["detail"] = f"{type(exc).__name__}"
        report["markdown"] = deterministic_narrative(findings, decisions, run_metadata)
    return report
