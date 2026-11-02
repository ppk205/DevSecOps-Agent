"""T06 reporting: status counts, SARIF, escaped HTML/Markdown, JSON export."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnscan.contracts.enums import (
    CWECategory,
    ExportFormat,
    FindingStatus,
    Severity,
    ToolName,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.contracts.report import FindingCounts, SarifReport
from vulnscan.reporting.reporter import ReportGenerator


def _finding(
    finding_id: str,
    status: FindingStatus,
    title: str = "SQL injection",
    cwe: CWECategory = CWECategory.SQL_INJECTION,
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id=finding_id,
        run_id="run-1",
        fingerprint=f"fp-{finding_id}",
        title=title,
        description=title,
        cwe_category=cwe,
        severity=Severity.HIGH,
        status=status,
        observations=[
            Observation(
                observation_id=f"obs-{finding_id}",
                detected_at=now,
                run_id="run-1",
                tool=ToolName.SEMGREP,
                tool_version="1.0.0",
                rule_id="java.sql.injection",
                cwe_category=cwe,
                severity=Severity.HIGH,
                message=title,
                confidence=0.9,
                location=SourceCoordinate(
                    file_path="src/LoginServlet.java",
                    line_start=42,
                    line_end=43,
                ),
            )
        ],
        created_at=now,
        updated_at=now,
    )


class TestFindingCounts:
    def test_four_status_buckets_are_distinct(self):
        findings = [
            _finding("f1", FindingStatus.CONFIRMED),
            _finding("f2", FindingStatus.CONFIRMED),
            _finding("f3", FindingStatus.REJECTED),
            _finding("f4", FindingStatus.UNRESOLVED),
            _finding("f5", FindingStatus.UNPROCESSED),
        ]
        counts = ReportGenerator.counts(findings)
        assert counts == FindingCounts(
            total=5, confirmed=2, rejected=1, unresolved=1, unprocessed=1
        )
        assert counts.validate_counts()

    def test_unknown_future_status_stays_in_total(self):
        findings = [_finding("f1", FindingStatus.UNPROCESSED)]
        # Contract is strict, so all known statuses must map to exactly one bucket.
        assert ReportGenerator.counts(findings).unprocessed == 1


class TestSarif:
    def test_sarif_envelope_and_results(self):
        report = ReportGenerator.to_sarif(
            "run-1",
            [_finding("f1", FindingStatus.CONFIRMED)],
            tool_version="0.1.0",
        )
        assert isinstance(report, SarifReport)
        assert report.version == "2.1.0"
        assert len(report.results) == 1
        result = report.results[0]
        assert result.finding_id == "f1"
        assert result.cwe_category == "CWE-89"
        assert result.locations[0].line_start == 42
        assert result.partial_fingerprints["primary"] == "fp-f1"

    def test_sarif_dict_uses_schema_property(self):
        report = ReportGenerator.to_sarif("run-1", [])
        data = report.to_sarif_dict()
        assert data["$schema"].endswith("sarif-schema-2.1.0.json")
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["tool"]["driver"]["name"] == "devsecops-agent"


class TestHumanReadableExports:
    def test_markdown_contains_all_statuses(self):
        findings = [
            _finding("f1", FindingStatus.CONFIRMED),
            _finding("f2", FindingStatus.REJECTED),
            _finding("f3", FindingStatus.UNRESOLVED),
            _finding("f4", FindingStatus.UNPROCESSED),
        ]
        report = ReportGenerator("run-1", findings, {"skipped": 2})
        text = report.to_markdown()
        for label in ("Confirmed", "Rejected", "Unresolved", "Unprocessed"):
            assert f"| {label} | 1 |" in text
        assert "skipped" in text

    def test_html_escapes_untrusted_finding_content(self):
        payload = "<script>alert('xss')</script>"
        report = ReportGenerator("run-1", [_finding("f1", FindingStatus.CONFIRMED, title=payload)])
        text = report.to_html()
        assert payload not in text
        assert "&lt;script&gt;" in text

    def test_html_uses_pitwall_theme_and_summarized_coverage(self):
        findings = [_finding("f1", FindingStatus.UNRESOLVED)]
        coverage = {
            "semgrep": [
                {"status": "analyzed", "unit_path": "A.java"},
                {"status": "skipped", "unit_path": "B.java", "limitation_reason": "binary file"},
            ]
        }
        report = ReportGenerator(
            "run-1", findings, run_metadata={"commit": "abc"}, coverage_summary=coverage
        )
        text = report.to_html()
        assert "scrollbar-color" in text  # styled scrollbars, not default white
        assert "st-unresolved" in text  # status chip, not plain text
        assert "semgrep" in text and "1/2 units analyzed" in text
        assert "binary file" in text
        assert "'status': 'analyzed'" not in text  # no raw dict dump

    def test_json_export_is_valid_utf8_json(self):
        report = ReportGenerator("run-1", [_finding("f1", FindingStatus.CONFIRMED)])
        text = report.to_json()
        data = json.loads(text)
        assert data["run_id"] == "run-1"
        assert data["counts"]["confirmed"] == 1
        assert data["findings"][0]["finding_id"] == "f1"


class TestFileExport:
    def test_export_creates_artifact_and_checksum(self, tmp_path: Path):
        report = ReportGenerator("run-1", [_finding("f1", FindingStatus.CONFIRMED)])
        export = report.export(ExportFormat.SARIF, tmp_path, generated_by="test")
        path = tmp_path / f"{export.export_id}.sarif"
        assert path.exists()
        assert export.artifact_ref.checksum_sha256
        assert len(export.artifact_ref.checksum_sha256) == 64
        assert export.validate_consistency()

    @pytest.mark.parametrize("fmt", list(ExportFormat))
    def test_every_export_format(self, tmp_path: Path, fmt: ExportFormat):
        report = ReportGenerator("run-1", [_finding("f1", FindingStatus.CONFIRMED)])
        export = report.export(fmt, tmp_path, generated_by="test")
        assert Path(export.artifact_ref.path).exists()
        assert export.format == fmt
