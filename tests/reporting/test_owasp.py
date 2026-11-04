"""FR-61: deterministic OWASP Top 10:2025 to normalized-CWE cross-reference."""

import io
import json

import pytest
from docx import Document

from tests.reporting.test_reporter import _finding
from vulnscan.contracts import CWECategory, FindingStatus
from vulnscan.reporting.owasp import build_owasp_summary
from vulnscan.reporting.reporter import ReportGenerator


def test_fr61_owasp_maps_official_2025_cwes_and_retains_actual_statuses():
    findings = [
        _finding("sql-confirmed", FindingStatus.CONFIRMED),
        _finding("sql-rejected", FindingStatus.REJECTED),
        _finding("ssrf-open", FindingStatus.UNRESOLVED, cwe=CWECategory.SSRF),
        _finding(
            "exception", FindingStatus.PENDING_VALIDATION, cwe=CWECategory.STACK_TRACE_EXPOSURE
        ),
    ]
    before = [f.model_dump(mode="json") for f in findings]
    data = build_owasp_summary(findings)
    assert data["edition"] == "2025" and len(data["categories"]) == 10
    categories = {c["id"]: c for c in data["categories"]}
    injection = categories["A05:2025"]
    assert injection["cwes"][0]["cwe"] == "CWE-89"
    assert injection["cwes"][0]["finding_ids"] == ["sql-confirmed", "sql-rejected"]
    assert injection["status_counts"]["confirmed"] == 1
    assert injection["status_counts"]["rejected"] == 1
    assert categories["A01:2025"]["finding_ids"] == ["ssrf-open"]
    assert categories["A10:2025"]["status_counts"]["pending_validation"] == 1
    assert categories["A02:2025"]["total"] == 0
    assert data["unmapped"] == []
    assert [f.model_dump(mode="json") for f in findings] == before


@pytest.mark.parametrize(
    ("cwe", "category"),
    [
        (CWECategory.SECURITY_MISCONFIGURATION, "A02:2025"),
        (CWECategory.DEPENDENCY_VULNERABILITY, "A03:2025"),
        (CWECategory.CRYPTOGRAPHIC_FAILURE, "A04:2025"),
        (CWECategory.AUTH_FAILURE, "A07:2025"),
        (CWECategory.INSECURE_DESERIALIZATION, "A08:2025"),
        (CWECategory.INSUFFICIENT_LOGGING, "A09:2025"),
    ],
)
def test_fr61_owasp_uses_published_category_membership(cwe, category):
    data = build_owasp_summary([_finding("finding", FindingStatus.UNPROCESSED, cwe=cwe)])
    assert [c["id"] for c in data["categories"] if c["total"]] == [category]


def test_fr61_unlisted_and_missing_cwes_are_explicit_not_inferred():
    missing = _finding("missing", FindingStatus.UNRESOLVED, cwe=CWECategory.UNCLASSIFIED)
    data = build_owasp_summary(
        [
            missing,
            _finding("unclassified", FindingStatus.REJECTED, cwe=CWECategory.UNCLASSIFIED),
            _finding("nosql", FindingStatus.TRIAGED, cwe=CWECategory.NOSQL_INJECTION),
        ]
    )
    assert not any(c["total"] for c in data["categories"])
    assert {f for row in data["unmapped"] for f in row["finding_ids"]} == {
        "missing",
        "unclassified",
        "nosql",
    }
    assert {row["reason"] for row in data["unmapped"]} == {
        "unclassified_cwe",
        "not_listed_in_owasp_2025",
    }


def test_fr61_multiple_observations_do_not_inflate_finding_counts():
    finding = _finding("one", FindingStatus.CONFIRMED)
    finding.observations.append(finding.observations[0].model_copy())
    category = next(
        c for c in build_owasp_summary([finding])["categories"] if c["id"] == "A05:2025"
    )
    assert category["total"] == 1 and category["cwes"][0]["total"] == 1


def test_fr61_structured_exports_share_cross_reference_and_cannot_override_it():
    findings = [_finding("sql", FindingStatus.UNRESOLVED)]
    report = ReportGenerator("run-1", findings, run_metadata={"owasp_top10": {"fake": "passed"}})
    expected = build_owasp_summary(report.findings)
    assert json.loads(report.to_json())["owasp_top10"] == expected
    assert report.sarif_document()["runs"][0]["properties"]["owasp_top10"] == expected
    assert ReportGenerator.to_sarif("run-1", findings).metadata["owasp_top10"] == expected


def test_fr61_primary_and_secondary_cwes_are_cross_referenced_once_per_category():
    finding = _finding("multi-cwe", FindingStatus.UNRESOLVED)
    finding.additional_cwe_labels = [
        CWECategory.XSS,
        CWECategory.SQL_INJECTION,
        CWECategory.AUTH_FAILURE,
    ]
    data = build_owasp_summary([finding])
    by_id = {c["id"]: c for c in data["categories"]}
    assert by_id["A05:2025"]["total"] == 1
    assert [row["cwe"] for row in by_id["A05:2025"]["cwes"]] == ["CWE-79", "CWE-89"]
    assert by_id["A07:2025"]["finding_ids"] == ["multi-cwe"]
    assert data["total_findings"] == 1


def test_fr61_human_formats_show_same_cwes_refs_and_empty_categories():
    report = ReportGenerator("run-1", [_finding("sql-ref", FindingStatus.CONFIRMED)])
    word = Document(io.BytesIO(report.to_docx_bytes()))
    word_text = "\n".join(
        [p.text for p in word.paragraphs]
        + [cell.text for t in word.tables for row in t.rows for cell in row.cells]
    )
    for text in [report.to_markdown(), report.to_txt(), report.to_html(), word_text]:
        assert "OWASP Top 10:2025" in text
        assert "CWE-89" in text and "sql-ref" in text
        for index in range(1, 11):
            assert f"A{index:02d}:2025" in text
        assert "not a coverage" in text


def test_fr61_empty_report_does_not_claim_owasp_checks_passed():
    data = build_owasp_summary([])
    assert len(data["categories"]) == 10
    assert data["total_findings"] == 0 and data["unmapped"] == []
    assert not any(row["total"] for row in data["categories"])
    text = ReportGenerator("empty", []).to_markdown()
    assert "No mapped findings reported" in text
    assert "OWASP checks passed" not in text


def test_fr61_owasp_table_escapes_untrusted_finding_references():
    finding = _finding("<script>alert(1)</script>|`bad`", FindingStatus.UNRESOLVED)
    report = ReportGenerator("run-1", [finding])
    for text in [report.to_html(), report.to_markdown()]:
        section = text.split("OWASP Top 10:2025", 1)[1].split("Findings", 1)[0]
        assert "<script>" not in section
        assert "&lt;script&gt;" in section
