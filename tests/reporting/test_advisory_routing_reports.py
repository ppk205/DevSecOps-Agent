"""Advisory routing must be visible in reports without ever owning status."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnscan.contracts.enums import (
    CWECategory,
    EvidenceStrength,
    FindingStatus,
    LanguageKind,
    Severity,
    ToolName,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.reporting.reporter import ReportGenerator


def _finding(finding_id: str = "F-1") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id=finding_id,
        run_id="R",
        fingerprint=f"fp-{finding_id}",
        title="SQL injection",
        description="Concatenated query",
        cwe_category=CWECategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        observations=[
            Observation(
                observation_id="O1",
                run_id="R",
                tool=ToolName.SEMGREP,
                tool_version="1.178.0",
                rule_id="java.lang.security",
                cwe_category=CWECategory.SQL_INJECTION,
                severity=Severity.HIGH,
                message="Concatenated query",
                location=SourceCoordinate(
                    file_path="src/Main.java",
                    language=LanguageKind.JAVA,
                    line_start=42,
                ),
                detected_at=now,
            )
        ],
        evidence_strength=EvidenceStrength.STRONG,
        created_at=now,
        updated_at=now,
    )


def _payload(route: str = "human_review", status: str = "completed") -> dict:
    return {
        "finding_id": "F-1",
        "route": route,
        "decision_status": status,
        "affects_finding_status": False,
        "model_id": "convaiinnovations/laya",
        "model_revision": "aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8",
        "input_truncated": False,
        "answers": {
            "recommended_action": {"type": "choice", "choice": "human_review"},
            "evidence_sufficiency": {"type": "score", "score": 0.83},
            "needs_human_review": {"type": "noul", "noul": 0.09},
        },
    }


def test_markdown_states_routing_is_advisory_only() -> None:
    md = ReportGenerator("R", [_finding()], routing_payloads=[_payload()]).to_markdown()

    assert "## Advisory routing" in md
    assert "Advisory only" in md
    assert "IndependentValidator` remains the sole owner" in md
    assert "Affects finding status: `false`" in md


def test_markdown_reports_route_counts() -> None:
    md = ReportGenerator(
        "R", [_finding()], routing_payloads=[_payload("human_review"), _payload("low_priority")]
    ).to_markdown()

    assert "| `human_review` | 1 |" in md
    assert "| `low_priority` | 1 |" in md


def test_markdown_surfaces_model_answers_per_finding() -> None:
    md = ReportGenerator("R", [_finding()], routing_payloads=[_payload()]).to_markdown()

    assert "**Advisory route:** `human_review`" in md
    assert "Needs human review (model):** 0.09" in md
    assert "Evidence sufficiency (model):** 0.83" in md


def test_markdown_states_absence_when_no_routing_ran() -> None:
    md = ReportGenerator("R", [_finding()]).to_markdown()

    assert "## Advisory routing" in md
    assert "did not run for this scan" in md


def test_markdown_counts_unusable_decisions() -> None:
    md = ReportGenerator(
        "R", [_finding()], routing_payloads=[_payload(status="unavailable")]
    ).to_markdown()

    assert "Findings without a usable model decision: 1" in md


def test_markdown_escapes_route_values() -> None:
    md = ReportGenerator("R", [_finding()], routing_payloads=[_payload("<script>")]).to_markdown()

    assert "<script>" not in md
    assert "&lt;script&gt;" in md


def test_json_declares_advisory_and_never_status_authority() -> None:
    data = json.loads(ReportGenerator("R", [_finding()], routing_payloads=[_payload()]).to_json())

    advisory = data["advisory_routing"]
    assert advisory["is_advisory_only"] is True
    assert advisory["affects_finding_status"] is False
    assert advisory["routed"] == 1
    assert advisory["unavailable"] == 0
    assert advisory["route_counts"] == {"human_review": 1}


def test_json_reports_empty_routing_without_failing() -> None:
    data = json.loads(ReportGenerator("R", [_finding()]).to_json())

    advisory = data["advisory_routing"]
    assert advisory["routed"] == 0
    assert advisory["route_counts"] == {}
    assert advisory["payloads"] == []


def test_reporting_never_changes_finding_status() -> None:
    finding = _finding()
    before = finding.status

    ReportGenerator("R", [finding], routing_payloads=[_payload(status="unavailable")]).to_markdown()

    assert finding.status is before


@pytest.mark.parametrize("fmt", ["json", "markdown", "html", "sarif"])
def test_every_format_still_renders(fmt: str, tmp_path) -> None:
    export = ReportGenerator("R", [_finding()], routing_payloads=[_payload()]).export(
        fmt, tmp_path
    )

    assert export.artifact_ref.path
    assert export.format.value == fmt
    assert export.counts.total == 1
    assert Path(export.artifact_ref.path).stat().st_size > 0
