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
from vulnscan.version import APP_VERSION

_MIME = {
    ExportFormat.SARIF: "application/sarif+json",
    ExportFormat.JSON: "application/json",
    ExportFormat.HTML: "text/html",
    ExportFormat.MARKDOWN: "text/markdown",
}
_SUFFIX = {
    ExportFormat.SARIF: "sarif",
    ExportFormat.JSON: "json",
    ExportFormat.HTML: "html",
    ExportFormat.MARKDOWN: "md",
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
            metadata={"counts": cls.counts(findings).model_dump(mode="json")},
        )

    def sarif_document(self) -> dict[str, Any]:
        document = self.to_sarif(self.run_id, self.findings).to_sarif_dict()
        run = document["runs"][0]
        run["properties"].update(self.run_metadata)
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
            f"Scan metadata: {html.escape(str(self.run_metadata))}",
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

    def to_html(self) -> str:
        counts = self.counts(self.findings)
        env = Environment(autoescape=select_autoescape(default=True))
        template = env.from_string(_HTML_TEMPLATE)
        return template.render(
            run_id=self.run_id,
            application_version=APP_VERSION,
            run_metadata=self.run_metadata,
            counts=counts,
            findings=self.findings,
            coverage_summary=self.coverage_summary,
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
        content = {
            ExportFormat.SARIF: lambda: json.dumps(self.sarif_document(), indent=2),
            ExportFormat.JSON: self.to_json,
            ExportFormat.HTML: self.to_html,
            ExportFormat.MARKDOWN: self.to_markdown,
        }[fmt]()
        encoded = content.encode("utf-8")
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


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Security assessment {{ run_id }}</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#17202a}
h1{font-size:28px} .counts{display:flex;gap:20px;padding:0;list-style:none}
.counts li{border-left:3px solid #64748b;padding-left:12px}.count{font-size:28px;font-weight:700}
.finding{border-top:1px solid #d8dee6;padding:20px 0}.meta{color:#52606d;font-size:13px}
code{background:#eef2f6;padding:2px 5px}a{color:#075985}@media print{body{margin:20px}}
</style></head><body>
<h1>Security assessment <code>{{ run_id }}</code></h1>
<p class="meta">devsecops-agent {{ application_version }} | {{ run_metadata }}</p>
<ul class="counts">
<li><span class="count">{{ counts.total }}</span><br>Total</li>
<li><span class="count">{{ counts.confirmed }}</span><br>Confirmed</li>
<li><span class="count">{{ counts.rejected }}</span><br>Rejected</li>
<li><span class="count">{{ counts.unresolved }}</span><br>Unresolved</li>
<li><span class="count">{{ counts.unprocessed }}</span><br>Unprocessed</li>
</ul>
<h2>Coverage limitations</h2>
{% if coverage_summary %}<ul>{% for k, v in coverage_summary.items() %}<li><strong>{{ k }}</strong>: {{ v }}</li>{% endfor %}</ul>{% else %}<p>No limitations recorded.</p>{% endif %}
<h2>Findings</h2>
{% for f in findings %}<section class="finding"><h3>{{ f.title }}</h3>
<p class="meta">{{ f.finding_id }} · {{ f.status.value }} · {{ f.severity.value }} · {{ f.cwe_category.value if f.cwe_category else "Unclassified" }}</p>
<p>{{ f.description }}</p>
{% for observation in f.observations %}<p class="meta">{{ observation.tool.value }} / {{ observation.rule_id }} / {{ observation.location.as_string() }}</p>
{% if observation.location.snippet %}<pre>{{ observation.location.snippet }}</pre>{% endif %}{% endfor %}
</section>{% endfor %}
</body></html>"""


__all__ = ["ReportGenerator"]
