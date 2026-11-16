"""Summary events derived from actual scan results, never raw scan contents."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
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


def _webhook_text(value: str) -> str:
    safe = str(sanitize(redact(value)))
    safe = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", safe)
    return str(sanitize(redact(safe)))


def build_webhook_body(
    run_id: str,
    scan_status: str,
    events: Sequence[Mapping[str, str]],
    delivery_id: str,
) -> bytes:
    """Copy selected retained summaries into the canonical schema-1 envelope."""
    if (
        not all(isinstance(value, str) for value in (run_id, scan_status, delivery_id))
        or not isinstance(events, Sequence)
        or isinstance(events, (str, bytes))
    ):
        raise ValueError("Invalid webhook summary")
    selected: list[dict[str, str]] = []
    for event in events:
        if (
            not isinstance(event, Mapping)
            or not isinstance(event.get("kind"), str)
            or event["kind"] not in EVENT_LABELS
            or not isinstance(event.get("message"), str)
        ):
            raise ValueError("Invalid webhook summary")
        selected.append({"kind": event["kind"], "message": _webhook_text(event["message"])[:1800]})
    envelope = {
        "schema_version": 1,
        "delivery_id": _webhook_text(delivery_id),
        "run_id": _webhook_text(run_id)[:100],
        "scan_status": _webhook_text(scan_status),
        "events": selected,
    }
    try:
        body = json.dumps(
            envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except UnicodeError:
        raise ValueError("Invalid webhook summary") from None
    if len(body) > 16384:
        raise ValueError("Webhook summary exceeds 16 KiB")
    return body


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
