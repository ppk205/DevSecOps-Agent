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


def test_empty_model_reply_falls_back_to_deterministic_narrative(monkeypatch):
    """Empty AI reply must not produce a 0-byte report: deterministic text + partial."""
    from vulnscan.reporting import final_report as fr_mod
    from vulnscan.reporting.final_report import run_final_report

    class _Resp:
        content = "   "
        model = "test-model"
        usage = {"total_tokens": 0}  # noqa: RUF012 - test stub, never mutated

    class _Client:
        def __init__(self, *a, **k):
            pass

        def chat(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(fr_mod, "ProviderClient", _Client)
    from types import SimpleNamespace

    monkeypatch.setattr(
        fr_mod, "load_profile", lambda pid: SimpleNamespace(id=pid, default_model="m")
    )
    out = run_final_report(
        [_finding()],
        [],
        {"target": "x", "commit": "y", "gate": "failed", "status": "failed"},
        profile_id="any-profile",
        model="m",
    )
    assert out["status"] == "partial"
    assert out["ai_written"] is False
    assert "empty reply" in out["detail"]
    assert len(out["markdown"]) > 100
