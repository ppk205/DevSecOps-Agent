"""Single-source report generation for JSON, SARIF, HTML, and Markdown."""

from __future__ import annotations

import hashlib
import html
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from vulnscan.contracts.artifact import ArtifactReference
from vulnscan.contracts.enums import ExportFormat, FindingStatus
from vulnscan.contracts.finding import Finding
from vulnscan.contracts.report import (
    FindingCounts,
    ReportExport,
    SarifLocation,
    SarifReport,
    SarifResult,
)
from vulnscan.core.security import sanitize
from vulnscan.reporting.owasp import (
    NOTE as OWASP_NOTE,
)
from vulnscan.reporting.owasp import (
    SECTION_TITLE as OWASP_TITLE,
)
from vulnscan.reporting.owasp import (
    SOURCE_URL as OWASP_SOURCE,
)
from vulnscan.reporting.owasp import (
    TABLE_HEADERS as OWASP_HEADERS,
)
from vulnscan.reporting.owasp import (
    build_owasp_summary,
)
from vulnscan.reporting.owasp import (
    markdown_section as owasp_markdown,
)
from vulnscan.reporting.owasp import (
    table_rows as owasp_rows,
)
from vulnscan.version import APP_VERSION

_MIME = {
    ExportFormat.SARIF: "application/sarif+json",
    ExportFormat.JSON: "application/json",
    ExportFormat.HTML: "text/html",
    ExportFormat.MARKDOWN: "text/markdown",
    ExportFormat.TXT: "text/plain",
    ExportFormat.DOCX: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
_SUFFIX = {
    ExportFormat.SARIF: "sarif",
    ExportFormat.JSON: "json",
    ExportFormat.HTML: "html",
    ExportFormat.MARKDOWN: "md",
    ExportFormat.TXT: "txt",
    ExportFormat.DOCX: "docx",
}


class ReportGenerator:
    """Generate consistent, escaped reports from one run's findings."""

    def __init__(
        self,
        run_id: str,
        findings: list[Finding],
        coverage_summary: dict[str, Any] | None = None,
        routing_payloads: list[dict[str, Any]] | None = None,
        run_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.run_id = run_id
        self.findings = [
            Finding.model_validate(sanitize(f.model_dump(mode="json"))) for f in findings
        ]
        self.coverage_summary = sanitize(coverage_summary or {})
        self.routing_payloads = sanitize(routing_payloads or [])
        self.run_metadata = sanitize(run_metadata or {})

    def routing_by_finding(self) -> dict[str, dict[str, Any]]:
        """Advisory routing payloads keyed by finding id."""
        return {str(p.get("finding_id")): p for p in self.routing_payloads}

    def routing_counts(self) -> dict[str, int]:
        """How many findings took each route, including the fallback."""
        counts: dict[str, int] = {}
        for payload in self.routing_payloads:
            route = str(payload.get("route", "unknown"))
            counts[route] = counts.get(route, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def advisory_unavailable(self) -> list[dict[str, Any]]:
        """Payloads where the model did not return a usable decision."""
        return [
            p for p in self.routing_payloads if str(p.get("decision_status", "")) != "completed"
        ]

    @staticmethod
    def counts(findings: list[Finding]) -> FindingCounts:
        """Partition findings into the four mandatory status buckets."""
        buckets = {
            FindingStatus.CONFIRMED: 0,
            FindingStatus.REJECTED: 0,
            FindingStatus.UNRESOLVED: 0,
            FindingStatus.UNPROCESSED: 0,
        }
        for finding in findings:
            if finding.status in buckets:
                buckets[finding.status] += 1
        return FindingCounts(
            total=len(findings),
            confirmed=buckets[FindingStatus.CONFIRMED],
            rejected=buckets[FindingStatus.REJECTED],
            unresolved=buckets[FindingStatus.UNRESOLVED],
            unprocessed=len(findings)
            - sum(v for k, v in buckets.items() if k != FindingStatus.UNPROCESSED),
        )

    @classmethod
    def to_sarif(
        cls,
        run_id: str,
        findings: list[Finding],
        tool_version: str = APP_VERSION,
    ) -> SarifReport:
        results: list[SarifResult] = []
        for finding in findings:
            locations: list[SarifLocation] = []
            for observation in finding.observations:
                if observation.location is None:
                    continue
                loc = observation.location
                locations.append(
                    SarifLocation(
                        file_path=loc.file_path,
                        line_start=loc.line_start,
                        line_end=loc.line_end,
                        column_start=loc.column_start,
                        column_end=loc.column_end,
                    )
                )
            results.append(
                SarifResult(
                    rule_id=(
                        finding.observations[0].rule_id
                        if finding.observations
                        else finding.finding_id
                    ),
                    rule_name=finding.title,
                    cwe_category=(finding.cwe_category.value if finding.cwe_category else None),
                    severity=finding.severity,
                    message=finding.description or finding.title,
                    locations=locations,
                    finding_id=finding.finding_id,
                    partial_fingerprints={"primary": finding.fingerprint},
                )
            )
        return SarifReport(
            run_id=run_id,
            generated_at=datetime.now(UTC),
            tool_name="devsecops-agent",
            tool_version=tool_version,
            results=results,
            metadata={
                "counts": cls.counts(findings).model_dump(mode="json"),
                "owasp_top10": build_owasp_summary(findings),
            },
        )

    def sarif_document(self) -> dict[str, Any]:
        document = self.to_sarif(self.run_id, self.findings).to_sarif_dict()
        run = document["runs"][0]
        run["properties"].update(self.run_metadata)
        run["properties"]["owasp_top10"] = build_owasp_summary(self.findings)
        if "status" in self.run_metadata:
            run["invocations"] = [
                {
                    "executionSuccessful": self.run_metadata["status"] == "completed",
                    "toolExecutionNotifications": [
                        {"level": "error", "message": {"text": str(error)}}
                        for error in self.run_metadata.get("errors", [])
                    ],
                }
            ]
        return document

    def to_json(self) -> str:
        data = {
            "application_version": APP_VERSION,
            "scan_metadata": self.run_metadata,
            "run_id": self.run_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "counts": self.counts(self.findings).model_dump(mode="json"),
            "coverage_summary": self.coverage_summary,
            "owasp_top10": build_owasp_summary(self.findings),
            "findings": [f.model_dump(mode="json") for f in self.findings],
            "advisory_routing": {
                "is_advisory_only": True,
                "affects_finding_status": False,
                "note": (
                    "Advisory recommendations never set or change a finding status; "
                    "IndependentValidator remains the sole status owner."
                ),
                "route_counts": self.routing_counts(),
                "routed": len(self.routing_payloads),
                "unavailable": len(self.advisory_unavailable()),
                "payloads": self.routing_payloads,
            },
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def advisory_section(self) -> list[str]:
        """Markdown for the advisory routing block, or a stated absence."""
        if not self.routing_payloads:
            absent = (
                "Laya advisory routing did not run for this scan "
                "(disabled, unavailable, or no findings to route)."
            )
            return ["", "## Advisory routing", "", absent]

        lines = [
            "",
            "## Advisory routing",
            "",
            (
                "> Advisory only. These recommendations do not set or change any "
                "finding status — `IndependentValidator` remains the sole owner."
            ),
            "",
            "| Route | Findings |",
            "|---|---:|",
        ]
        lines.extend(
            f"| `{html.escape(route)}` | {count} |"
            for route, count in self.routing_counts().items()
        )

        unavailable = self.advisory_unavailable()
        lines.extend(["", f"- Findings routed: {len(self.routing_payloads)}"])
        lines.append(f"- Findings without a usable model decision: {len(unavailable)}")

        revisions = {
            str(p.get("model_revision")) for p in self.routing_payloads if p.get("model_revision")
        }
        if revisions:
            lines.append(f"- Model revision(s): `{', '.join(sorted(revisions))}`")
        truncated = sum(1 for p in self.routing_payloads if p.get("input_truncated"))
        if truncated:
            lines.append(f"- Inputs truncated: {truncated}")
        lines.append("- Affects finding status: `false`")
        return lines

    def to_markdown(self) -> str:
        counts = self.counts(self.findings)
        lines = [
            f"# Security assessment — `{self.run_id}`",
            "",
            "## Finding status",
            "",
            "| Status | Count |",
            "|---|---:|",
            f"| Total | {counts.total} |",
            f"| Confirmed | {counts.confirmed} |",
            f"| Rejected | {counts.rejected} |",
            f"| Unresolved | {counts.unresolved} |",
            f"| Unprocessed | {counts.unprocessed} |",
            "",
            f"Generated by devsecops-agent {APP_VERSION}",
            f"Scan metadata: {self._display_metadata()}",
            "",
            "## Coverage limitations",
            "",
        ]
        if self.coverage_summary:
            lines.extend(
                f"- **{html.escape(str(k))}**: {html.escape(str(v))}"
                for k, v in self.coverage_summary.items()
            )
        else:
            lines.append("No coverage limitations recorded.")
        lines.extend(self.advisory_section())
        lines.extend(["", owasp_markdown(self.findings)])
        lines.extend(["", "## Findings", ""])
        routing = self.routing_by_finding()
        for finding in self.findings:
            cwe = finding.cwe_category.value if finding.cwe_category else "Unclassified"
            lines.extend(
                [
                    f"### {html.escape(finding.title)}",
                    "",
                    f"- **ID:** `{finding.finding_id}`",
                    f"- **Status:** {finding.status.value}",
                    f"- **Severity:** {finding.severity.value}",
                    f"- **CWE:** {cwe}",
                ]
            )
            payload = routing.get(finding.finding_id)
            if payload:
                answers = payload.get("answers", {})
                review = (answers.get("needs_human_review") or {}).get("noul", "n/a")
                sufficiency = (answers.get("evidence_sufficiency") or {}).get("score", "n/a")
                route = html.escape(str(payload.get("route", "")))
                lines.extend(
                    [
                        f"- **Advisory route:** `{route}`",
                        f"- **Needs human review (model):** {html.escape(str(review))}",
                        f"- **Evidence sufficiency (model):** {html.escape(str(sufficiency))}",
                    ]
                )
            lines.extend(["", html.escape(finding.description or ""), ""])
            for observation in finding.observations:
                loc = observation.location
                lines.extend(
                    [
                        f"- Source: {html.escape(loc.as_string())} ({observation.tool.value}, {html.escape(observation.rule_id)})",
                        "",
                    ]
                )
                if loc.snippet:
                    lines.extend(["<pre>" + html.escape(loc.snippet) + "</pre>", ""])
        return "\n".join(lines)

    def to_txt(self) -> str:
        """Plain-text rendering of the same single-source report data."""
        counts = self.counts(self.findings)
        lines = [
            f"Security assessment — {self.run_id}",
            "",
            "Finding status:",
            f"  Total:       {counts.total}",
            f"  Confirmed:   {counts.confirmed}",
            f"  Rejected:    {counts.rejected}",
            f"  Unresolved:  {counts.unresolved}",
            f"  Unprocessed: {counts.unprocessed}",
            "",
            f"Generated by devsecops-agent {APP_VERSION}",
            f"Scan metadata: {self._display_metadata()}",
            "",
            "Coverage limitations:",
        ]
        if self.coverage_summary:
            lines.extend(f"  - {k}: {v}" for k, v in self.coverage_summary.items())
        else:
            lines.append("  No coverage limitations recorded.")
        lines.extend(["", "Advisory routing:"])
        for route, count in self.routing_counts().items():
            lines.append(f"  - {route}: {count}")
        lines.extend(
            [
                f"  Findings routed: {len(self.routing_payloads)}",
                f"  Without a usable model decision: {len(self.advisory_unavailable())}",
                "  Affects finding status: false",
            ]
        )
        lines.extend(["", OWASP_TITLE, "", OWASP_NOTE, ""])
        for row in owasp_rows(build_owasp_summary(self.findings)):
            lines.append(" | ".join(row))
        lines.extend([f"Mapping source: {OWASP_SOURCE}", "", "Findings:"])
        for finding in self.findings:
            cwe = finding.cwe_category.value if finding.cwe_category else "Unclassified"
            lines.extend(
                [
                    "",
                    f"### {finding.title}",
                    f"  ID:       {finding.finding_id}",
                    f"  Status:   {finding.status.value}",
                    f"  Severity: {finding.severity.value}",
                    f"  CWE:      {cwe}",
                    "",
                    f"  {finding.description or ''}",
                ]
            )
            for observation in finding.observations:
                loc = observation.location
                if loc:
                    lines.append(
                        f"  - Source: {loc.as_string()} ({observation.tool.value}, {observation.rule_id})"
                    )
                    if loc.snippet:
                        lines.extend(f"    {s}" for s in loc.snippet.splitlines()[:8])
        return "\n".join(lines)

    def to_docx_bytes(self) -> bytes:
        """Word rendering of the same single-source report data."""
        from docx import Document
        from docx.shared import Pt

        doc = Document()
        doc.add_heading(f"Security assessment — {self.run_id}", level=1)
        counts = self.counts(self.findings)
        doc.add_paragraph(
            f"Generated by devsecops-agent {APP_VERSION} | Scan metadata: {self._display_metadata()}"
        )
        table = doc.add_table(rows=6, cols=2)
        for row, (label, value) in enumerate(
            [
                ("Total", counts.total),
                ("Confirmed", counts.confirmed),
                ("Rejected", counts.rejected),
                ("Unresolved", counts.unresolved),
                ("Unprocessed", counts.unprocessed),
            ]
            + [("Findings routed", len(self.routing_payloads))]
        ):
            if row >= len(table.rows):
                break
            table.rows[row].cells[0].text = label
            table.rows[row].cells[1].text = str(value)
        doc.add_heading(OWASP_TITLE, level=2)
        doc.add_paragraph(OWASP_NOTE)
        owasp_table = doc.add_table(rows=1, cols=len(OWASP_HEADERS))
        for cell, header in zip(owasp_table.rows[0].cells, OWASP_HEADERS, strict=True):
            cell.text = header
        for values in owasp_rows(build_owasp_summary(self.findings)):
            cells = owasp_table.add_row().cells
            for cell, content in zip(cells, values, strict=True):
                cell.text = content
        doc.add_paragraph(f"Mapping source: {OWASP_SOURCE}")
        doc.add_heading("Findings", level=2)
        routing = self.routing_by_finding()
        for finding in self.findings:
            cwe = finding.cwe_category.value if finding.cwe_category else "Unclassified"
            doc.add_heading(finding.title, level=3)
            doc.add_paragraph(
                f"ID: {finding.finding_id} | Status: {finding.status.value} | "
                f"Severity: {finding.severity.value} | CWE: {cwe}"
            )
            payload = routing.get(finding.finding_id)
            if payload:
                doc.add_paragraph(f"Advisory route: {payload.get('route', '')} (status-neutral)")
            if finding.description:
                doc.add_paragraph(finding.description)
            for observation in finding.observations:
                loc = observation.location
                if loc:
                    doc.add_paragraph(
                        f"Source: {loc.as_string()} ({observation.tool.value}, {observation.rule_id})"
                    )
                    if loc.snippet:
                        snippet = "\n".join(loc.snippet.splitlines()[:8])
                        run = doc.add_paragraph().add_run(snippet)
                        run.font.name = "Consolas"
                        run.font.size = Pt(8)
        import io

        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue()

    def _display_metadata(self) -> dict[str, Any]:
        """run_metadata with a capped errors list for human formats.

        Full per-file coverage notes stay in JSON/SARIF; human formats get
        the first entries plus a count so one scan cannot render a wall of
        hundreds of lines.
        """
        meta = dict(self.run_metadata)
        errors = list(meta.get("errors", []) or [])
        if len(errors) > 10:
            meta["errors"] = errors[:10] + [
                f"... and {len(errors) - 10} more (see JSON/SARIF export)"
            ]
        return meta

    def to_html(self) -> str:
        counts = self.counts(self.findings)
        env = Environment(autoescape=select_autoescape(default=True))
        template = env.from_string(_HTML_TEMPLATE)
        return template.render(
            run_id=self.run_id,
            application_version=APP_VERSION,
            run_metadata=self._display_metadata(),
            counts=counts,
            findings=self.findings,
            coverage_summary=self.coverage_summary,
            coverage_cards=_coverage_cards(self.coverage_summary),
            owasp_title=OWASP_TITLE,
            owasp_note=OWASP_NOTE,
            owasp_source=OWASP_SOURCE,
            owasp_headers=OWASP_HEADERS,
            owasp_rows=owasp_rows(build_owasp_summary(self.findings)),
        )

    def export(
        self,
        fmt: ExportFormat,
        output_dir: str | Path,
        generated_by: str = "system",
    ) -> ReportExport:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        export_id = f"export-{uuid.uuid4().hex[:12]}"
        path = output / f"{export_id}.{_SUFFIX[fmt]}"
        if fmt is ExportFormat.DOCX:
            content_bytes: bytes = self.to_docx_bytes()
            encoded = content_bytes
        else:
            text = {
                ExportFormat.SARIF: lambda: json.dumps(self.sarif_document(), indent=2),
                ExportFormat.JSON: self.to_json,
                ExportFormat.HTML: self.to_html,
                ExportFormat.MARKDOWN: self.to_markdown,
                ExportFormat.TXT: self.to_txt,
            }[fmt]()
            encoded = text.encode("utf-8")
        path.write_bytes(encoded)
        artifact = ArtifactReference(
            path=str(path),
            checksum_sha256=hashlib.sha256(encoded).hexdigest(),
            mime_type=_MIME[fmt],
            size_bytes=len(encoded),
        )
        return ReportExport(
            export_id=export_id,
            run_id=self.run_id,
            format=fmt,
            artifact_ref=artifact,
            counts=self.counts(self.findings),
            coverage_summary=self.coverage_summary,
            generated_at=datetime.now(UTC),
            generated_by=generated_by,
        )


def _coverage_cards(coverage_summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Summarize per-tool coverage for the HTML report.

    The stored payload is a mapping of tool name to coverage records (or
    record-like dicts). Dumping it raw produces a wall of repr text, so
    collapse each tool to unit counts plus the distinct limitation reasons.
    Unknown shapes degrade to a short record count instead of raising.
    """
    cards: list[dict[str, Any]] = []
    for tool, records in (coverage_summary or {}).items():
        items = records if isinstance(records, list) else [records]
        units = len(items)
        analyzed = 0
        reasons: list[str] = []
        for record in items:
            if not isinstance(record, dict):
                continue
            if str(record.get("status", "")).lower() == "analyzed":
                analyzed += 1
            reason = record.get("limitation_reason") or record.get("reason")
            if reason and str(reason) not in reasons:
                reasons.append(str(reason))
        cards.append(
            {
                "tool": str(tool),
                "units": units,
                "analyzed": analyzed,
                "limitations": reasons[:8],
            }
        )
    return cards


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8\">
<meta name="viewport" content="width=device-width, initial-scale=1\">
<title>Security assessment {{ run_id }}</title>
<style>
:root{--bg:#0e1319;--card:#161d24;--ink:#e8edf2;--muted:#9aa7b4;--hairline:#2a3440;
--accent:#1c69d4;--green:#22c55e;--yellow:#f59e0b;--red:#e22718;--code:#0b0f14}
*{box-sizing:border-box}html{scrollbar-color:#3a4654 var(--bg)}
body{font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;max-width:1100px;
margin:40px auto;padding:0 20px;background:var(--bg);color:var(--ink)}
h1{font-size:28px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px;
padding-bottom:8px;border-bottom:1px solid var(--hairline)}
a{color:#6ea8fe}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:.86em;background:var(--code);border:1px solid var(--hairline);
border-radius:4px;padding:2px 6px}
.meta{color:var(--muted);font-size:13px}.chips{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.chip{font-size:12px;border:1px solid var(--hairline);border-radius:999px;padding:3px 12px;color:var(--muted)}
.counts{display:flex;flex-wrap:wrap;gap:12px;padding:0;list-style:none;margin:20px 0}
.counts li{flex:1 1 140px;background:var(--card);border:1px solid var(--hairline);
border-left:4px solid var(--muted);border-radius:6px;padding:10px 14px}
.counts li.ok{border-left-color:var(--green)}.counts li.warn{border-left-color:var(--yellow)}
.counts li.bad{border-left-color:var(--red)}
.count{font-size:28px;font-weight:700;line-height:1.1}.counts small{color:var(--muted)}
.finding{background:var(--card);border:1px solid var(--hairline);border-radius:8px;
padding:18px 20px;margin:14px 0}
.finding h3{margin:0 0 6px;font-size:16px}
.st{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;
border-radius:4px;padding:2px 8px;margin-right:6px}
.st-confirmed{background:rgba(34,197,94,.15);color:var(--green);border:1px solid var(--green)}
.st-unresolved,.st-unprocessed{background:rgba(245,158,11,.13);color:var(--yellow);border:1px solid var(--yellow)}
.st-rejected{background:rgba(154,167,180,.13);color:var(--muted);border:1px solid var(--muted)}
.sev-high{color:var(--red)}.sev-medium{color:var(--yellow)}.sev-low{color:#6ea8fe}
pre{background:var(--code);border:1px solid var(--hairline);border-radius:6px;
padding:12px 14px;overflow-x:auto;font-size:13px;line-height:1.5;scrollbar-color:#3a4654 var(--code)}
pre::-webkit-scrollbar{height:10px}pre::-webkit-scrollbar-track{background:var(--code)}
pre::-webkit-scrollbar-thumb{background:#3a4654;border-radius:5px}
pre::-webkit-scrollbar-thumb:hover{background:#4d5c6e}
::-webkit-scrollbar{width:12px;height:12px}::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#3a4654;border-radius:6px}
::-webkit-scrollbar-thumb:hover{background:#4d5c6e}
.cover{background:var(--card);border:1px solid var(--hairline);border-radius:8px;
padding:12px 16px;margin:10px 0}
.cover b{color:var(--ink)}.cover ul{margin:6px 0 0;padding-left:20px;color:var(--muted)}
.owasp{overflow-x:auto}.owasp table{width:100%;border-collapse:collapse;font-size:13px}
.owasp th,.owasp td{border:1px solid var(--hairline);padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
@media print{body{margin:20px;background:#fff;color:#000}.finding,.counts li,.cover{break-inside:avoid}}
</style></head><body>
<h1>Security assessment <code>{{ run_id }}</code></h1>
<p class="meta">devsecops-agent {{ application_version }}</p>
<div class="chips">{% for k, v in run_metadata.items() %}<span class="chip">{{ k }}: {{ v }}</span>{% endfor %}</div>
<ul class="counts">
<li class="ok"><span class="count">{{ counts.total }}</span><br><small>Total</small></li>
<li class="ok"><span class="count">{{ counts.confirmed }}</span><br><small>Confirmed</small></li>
<li><span class="count">{{ counts.rejected }}</span><br><small>Rejected</small></li>
<li class="warn"><span class="count">{{ counts.unresolved }}</span><br><small>Unresolved</small></li>
<li class="warn"><span class="count">{{ counts.unprocessed }}</span><br><small>Unprocessed</small></li>
</ul>
<h2>Coverage</h2>
{% if coverage_cards %}{% for card in coverage_cards %}<div class="cover"><b>{{ card.tool }}</b>
<span class="meta"> — {{ card.analyzed }}/{{ card.units }} units analyzed</span>
{% if card.limitations %}<ul>{% for reason in card.limitations %}<li>{{ reason }}</li>{% endfor %}</ul>{% endif %}</div>{% endfor %}
{% else %}<p class="meta">No coverage recorded.</p>{% endif %}
<h2>{{ owasp_title }}</h2>
<p class="meta">{{ owasp_note }}</p>
<div class="owasp"><table><thead><tr>{% for header in owasp_headers %}<th scope="col">{{ header }}</th>{% endfor %}</tr></thead>
<tbody>{% for row in owasp_rows %}<tr>{% for cell in row %}<td>{{ cell }}</td>{% endfor %}</tr>{% endfor %}</tbody></table></div>
<p class="meta">Mapping source: <a href="{{ owasp_source }}">OWASP Top 10:2025</a></p>
<h2>Findings</h2>
{% for f in findings %}<section class="finding"><h3>{{ f.title }}</h3>
<p><span class="st st-{{ f.status.value }}">{{ f.status.value }}</span><span class="sev-{{ f.severity.value }}">{{ f.severity.value }}</span>
<span class="meta"> · {{ f.finding_id[:12] }} · {{ f.cwe_category.value if f.cwe_category else "Unclassified" }}</span></p>
<p>{{ f.description }}</p>
{% for observation in f.observations %}<p class="meta">{{ observation.tool.value }} / {{ observation.rule_id }} / {{ observation.location.as_string() }}</p>
{% if observation.location.snippet %}<pre>{{ observation.location.snippet }}</pre>{% endif %}{% endfor %}
</section>{% endfor %}
</body></html>"""


__all__ = ["ReportGenerator"]
