"""Summary events derived from actual scan results, never raw scan contents."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from vulnscan.contracts import Finding, FindingStatus, Severity
from vulnscan.core.policy import effective_severity
from vulnscan.core.security import sanitize
from vulnscan.providers.credentials import redact

NotificationKind = Literal[
    "scan_completed",
    "scan_failed",
    "scan_cancelled",
    "gate_failed",
    "high_critical_findings",
    "ai_failed",
    "report_ready",
]

EVENT_LABELS: dict[NotificationKind, str] = {
    "scan_completed": "Scan completed",
    "scan_failed": "Scan failed or interrupted",
    "scan_cancelled": "Scan cancelled",
    "gate_failed": "Security gate failed",
    "high_critical_findings": "High/Critical findings reported",
    "ai_failed": "AI support unavailable or failed",
    "report_ready": "Reports ready",
}


def events_for_scan(summary: dict[str, Any], findings: Sequence[Finding]) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    identity = redact(str(summary.get("run_id") or summary.get("id") or "unknown"))[:100]

    def add(kind: NotificationKind, message: str) -> None:
        events.append(
            {"kind": kind, "label": EVENT_LABELS[kind], "message": str(sanitize(redact(message)))}
        )

    status = summary.get("status")
    if status == "completed":
        add("scan_completed", f"Scan {identity} completed.")
    elif status in {"failed", "interrupted"}:
        add("scan_failed", f"Scan {identity} {status}.")
    elif status == "cancelled":
        add("scan_cancelled", f"Scan {identity} was cancelled.")
    if summary.get("gate") == "failed":
        add("gate_failed", f"Scan {identity}: security gate failed.")
    important = 0
    for finding in findings:
        if finding.status == FindingStatus.REJECTED:
            continue
        try:
            severity = effective_severity(finding)
        except (KeyError, ValueError):
            severity = finding.severity
        if severity in {Severity.HIGH, Severity.CRITICAL}:
            important += 1
    if important:
        add(
            "high_critical_findings",
            f"High/Critical findings reported: {important}. Review their evidence and status.",
        )
    config = summary.get("configuration") or {}
    usage = summary.get("ai_usage") or {}
    requested = config.get("mode") == "hunt" or config.get("ai_review") or config.get("ai_report")
    model_stages = [
        stage
        for stage in summary.get("stages", [])
        if stage.get("stage") in {"model_hunt", "targeted_deep_analysis", "final_report"}
    ]
    failed_calls = usage.get("failed_requests", 0) or 0
    completed_calls = usage.get("completed_requests", 0) or 0
    if (
        status != "cancelled"
        and requested
        and (model_stages or failed_calls > 0)
        and (
            not config.get("provider_profile")
            or any(stage.get("status") in {"failed", "unavailable"} for stage in model_stages)
            or any(
                str(stage.get("message", "")).startswith("provider unavailable:")
                for stage in model_stages
            )
            or (failed_calls > 0 and completed_calls == 0)
        )
    ):
        add(
            "ai_failed",
            f"Scan {identity}: AI support was unavailable or failed. Check Activity for details.",
        )
    reports = summary.get("reports") or {}
    formats = sorted(str(name) for name, path in reports.items() if path)
    if formats:
        add(
            "report_ready",
            "Report formats available: "
            + ", ".join(formats)
            + f". Scan status: {status or 'unknown'}.",
        )
    return events
