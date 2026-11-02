"""Markdown and JSON export of a session: finding cards and the decision log."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from vulnscan.providers.credentials import redact

from .audit import SessionLog
from .workspace import ProposedFinding, Workspace

__all__ = ["export", "render_markdown"]

_STATUSES = ("proposed", "confirmed", "rejected", "need_more")


def _summary(ws: Workspace) -> str:
    counts = Counter(finding.status for finding in ws.findings.values())
    parts = [f"{counts[status]} {status}" for status in _STATUSES if counts[status]]
    return f"{len(ws.findings)} finding(s)" + (f": {', '.join(parts)}" if parts else "")


def _card(ws: Workspace, finding: ProposedFinding) -> list[str]:
    lines = [f"### {finding.id} {finding.title}", ""]
    lines.append(f"- CWE: {finding.cwe}")
    status = finding.status
    if finding.decided_by or finding.reason:
        status += f" (by {finding.decided_by or 'unknown'}: {finding.reason or 'no reason given'})"
    lines.append(f"- Status: {status}")

    candidate = ws.candidates.get(finding.candidate_id)
    if candidate is not None:
        confidence = (
            "n/a" if candidate.laya_confidence is None else f"{candidate.laya_confidence:.2f}"
        )
        lines.append(
            f"- Laya route: {candidate.laya_route or 'not triaged'} (confidence {confidence})"
        )

    lines.append("- Source to sink:")
    for number, hop in enumerate(finding.path, start=1):
        note = f" — {hop.note}" if hop.note else ""
        lines.append(f"  {number}. {hop.file}:{hop.line}{note}")
        lines.append("")
        lines.extend(f"     {code_line}" for code_line in (hop.code.splitlines() or [""]))
        lines.append("")
    lines.append("")
    lines.append(finding.explanation or "No explanation given.")
    lines.append("")

    score = "score unavailable" if finding.cvss_score is None else str(finding.cvss_score)
    lines.append(f"- CVSS: {finding.cvss_vector} → {score}")
    evidence = (
        "all citations verified"
        if not finding.evidence_errors
        else "; ".join(finding.evidence_errors)
    )
    lines.append(f"- Evidence check: {evidence}")

    fix = next((item for item in ws.fixes.values() if item.finding_id == finding.id), None)
    if fix is None:
        lines.append("- Fix: No fix proposed.")
    else:
        branch = f" on {fix.branch}" if fix.branch else ""
        lines.append(f"- Fix: {fix.status}{branch}")
        if fix.rescan:
            lines.append(f"- Re-scan: {fix.rescan}")
        lines.append("")
        lines.append("```diff")
        lines.extend(fix.diff.rstrip("\n").splitlines())
        lines.append("```")

    lines.append(f"- Tokens: {finding.tokens}")
    lines.append("")
    return lines


def _decision_log(log: SessionLog) -> list[str]:
    lines = ["## Decision log", ""]
    decisions = [event for event in log.events() if event.get("type") == "gate"]
    if not decisions:
        lines.extend(["None.", ""])
        return lines
    lines.append("| time | gate | choice | person | mode | reason |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for event in decisions:
        lines.append(
            f"| {event.get('at', '')} | {event.get('gate', '')} | {event.get('choice', '')} "
            f"| {event.get('person', '')} | {event.get('mode', '')} | {event.get('reason', '')} |"
        )
    lines.append("")
    return lines


def _session(log: SessionLog) -> list[str]:
    events = log.events()
    providers = sorted({str(e["provider"]) for e in events if e.get("provider")})
    models = sorted({str(e["model"]) for e in events if e.get("model")})
    totals = log.totals()
    lines = [
        "## Session",
        "",
        f"- Providers: {', '.join(providers) or 'unknown'}",
        f"- Models: {', '.join(models) or 'unknown'}",
        f"- Turns: {int(totals['turns'])}",
        f"- Tokens: {int(totals['input_tokens'])} in / {int(totals['output_tokens'])} out",
        f"- Cost: ${totals['cost_usd']:.4f}",
        "",
    ]
    return lines


def render_markdown(ws: Workspace, log: SessionLog) -> str:
    """Render the whole review as Markdown."""
    lines = [f"# Security review: {ws.target.name} @ {ws.commit[:12]}", ""]
    lines.append(_summary(ws))
    lines.append("")
    lines.append("## Awaiting human review")
    lines.append("")
    pending = sorted(f.id for f in ws.findings.values() if f.status == "proposed")
    lines.extend([f"- {finding_id}" for finding_id in pending] or ["None."])
    lines.append("")
    for finding in sorted(ws.findings.values(), key=lambda item: item.id):
        lines.extend(_card(ws, finding))
    lines.extend(_decision_log(log))
    lines.extend(_session(log))
    return redact("\n".join(lines))


def export(ws: Workspace, log: SessionLog, out_dir: Path) -> dict[str, Path]:
    """Write ``report.md`` and ``report.json`` under *out_dir*."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    markdown = out / "report.md"
    markdown.write_text(render_markdown(ws, log), encoding="utf-8")

    payload: dict[str, Any] = {
        "target": str(ws.target),
        "commit": ws.commit,
        "dirty": ws.dirty,
        "findings": [
            {
                "id": finding.id,
                "candidate_id": finding.candidate_id,
                "title": finding.title,
                "cwe": finding.cwe,
                "status": finding.status,
                "decided_by": finding.decided_by,
                "reason": finding.reason,
                "explanation": finding.explanation,
                "cvss_vector": finding.cvss_vector,
                "cvss_score": finding.cvss_score,
                "evidence_errors": finding.evidence_errors,
                "tokens": finding.tokens,
                "path": [
                    {"file": hop.file, "line": hop.line, "code": hop.code, "note": hop.note}
                    for hop in finding.path
                ],
            }
            for finding in sorted(ws.findings.values(), key=lambda item: item.id)
        ],
        "fixes": [
            {
                "id": fix.id,
                "finding_id": fix.finding_id,
                "status": fix.status,
                "branch": fix.branch,
                "rescan": fix.rescan,
                "diff": fix.diff,
                "test_hint": fix.test_hint,
            }
            for fix in sorted(ws.fixes.values(), key=lambda item: item.id)
        ],
        "decisions": [event for event in log.events() if event.get("type") == "gate"],
        "totals": log.totals(),
    }
    json_path = out / "report.json"
    json_path.write_text(redact(json.dumps(payload, indent=2, default=str)), encoding="utf-8")
    return {"markdown": markdown, "json": json_path}
