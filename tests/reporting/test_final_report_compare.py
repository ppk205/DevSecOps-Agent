"""Task 7: final report carries the model-vs-scanner comparison (Vietnamese)."""

from __future__ import annotations

from datetime import UTC, datetime

from vulnscan.contracts import (
    CWECategory,
    Finding,
    FindingStatus,
    Observation,
    Severity,
    SourceCoordinate,
    ToolName,
)
from vulnscan.reporting.final_report import build_report_prompt, deterministic_narrative


def _finding() -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id="f1",
        run_id="r1",
        fingerprint="fp-test",
        title="SQL Injection in login",
        description="User input flows to query",
        cwe_category=CWECategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        observations=[
            Observation(
                observation_id="obs-1",
                detected_at=now,
                run_id="r1",
                tool=ToolName.SEMGREP,
                tool_version="1.0",
                rule_id="java-sql-concatenation",
                cwe_category=CWECategory.SQL_INJECTION,
                severity=Severity.HIGH,
                message="SQL injection via request param",
                confidence=0.9,
                location=SourceCoordinate(file_path="src/LoginServlet.java", line_start=14),
            )
        ],
        created_at=now,
        updated_at=now,
    )


def _comparison() -> dict:
    finding = _finding()
    return {
        "agreed": [
            {
                "candidate": {
                    "title": "SQL concatenation in LoginServlet",
                    "file": "src/LoginServlet.java",
                    "line": 14,
                    "cwe": "CWE-89",
                },
                "finding": finding,
            }
        ],
        "model_only": [
            {
                "title": "Hardcoded secret",
                "file": "src/Config.java",
                "line": 7,
                "cwe": "CWE-798",
            }
        ],
        "scanner_only": [finding],
        "counts": {"agreed": 1, "model_only": 1, "scanner_only": 1},
    }


def test_deterministic_fallback_renders_compare_section():
    text = deterministic_narrative(
        [_finding()],
        [],
        {"target": "local", "commit": "abc", "gate": "failed"},
        comparison=_comparison(),
    )
    assert "## Đối chiếu model vs scanner" in text
    assert "src/LoginServlet.java:14" in text
    assert "src/Config.java:7" in text


def test_deterministic_fallback_without_compare_has_no_section():
    text = deterministic_narrative(
        [_finding()], [], {"target": "local", "commit": "abc", "gate": "failed"}
    )
    assert "Đối chiếu model vs scanner" not in text


def test_report_prompt_carries_compare_counts():
    prompt = build_report_prompt(
        [_finding()],
        [],
        {"target": "local", "commit": "abc", "gate": "pending"},
        comparison=_comparison(),
    )
    assert "Đối chiếu model vs scanner" in prompt
    assert '"agreed": 1' in prompt
