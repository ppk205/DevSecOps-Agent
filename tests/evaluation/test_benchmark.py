from typing import Any

import pytest

from vulnscan.evaluation.benchmark import compare_benchmark


def _run(
    run_id: int, scenario: str, **changes: Any
) -> tuple[int, str, dict[str, Any], dict[str, Any]]:
    ai_enabled = scenario != "A0"
    laya_enabled = scenario == "A3"
    configuration = {
        "mode": "hunt" if scenario == "A4" else "deterministic",
        "profile": "fast",
        "ai_review": ai_enabled,
        "ai_report": ai_enabled,
        "laya": laya_enabled,
        "max_ai_findings": 10 if scenario in {"A0", "A1"} else 5,
    }
    calls = [
        {
            "status": "completed",
            "stage": stage,
            "provider": "test-provider",
            "model": "test-model",
            "usage": {"prompt_tokens": 80, "completion_tokens": 20},
        }
        for stage in ("targeted_deep_analysis", "final_report")
        if ai_enabled
    ]
    spec = {
        "target_repository_url": "synthetic",
        "target_commit_sha": "abc123",
        "metadata": {"configuration": configuration},
        "tools": [{"tool": "native-hunt"}],
    }
    snapshot = {
        "configuration": configuration,
        "commit": "abc123",
        "manifest": {"files": {"file.java": "synthetic-hash"}},
        "exit_code": 1,
        "gate": "failed",
        "findings": 1,
        "scanner_results": [
            {
                "tool": "native-hunt",
                "status": "completed",
                "eligible_units": 1,
                "analyzed_units": 1,
                "skipped_units": 0,
                "coverage_records": [
                    {"unit_path": "file.java", "eligible": True, "status": "analyzed"}
                ],
            }
        ],
        "ai_usage": {
            "requests": len(calls),
            "http_attempts": len(calls),
            "completed_requests": len(calls),
            "failed_requests": 0,
        },
        "model_calls": calls,
        "stages": [
            {
                "stage": "targeted_deep_analysis",
                "status": "completed" if ai_enabled else "skipped",
            },
            {"stage": "laya_batch_routing", "status": "completed" if laya_enabled else "skipped"},
        ],
        "final_report": {"ai_written": ai_enabled, "status": "completed"},
        "routing": [{"decision_status": "completed", "device": "cuda"}] if laya_enabled else [],
        "duration_seconds": 15 if scenario == "A1" else 10,
        "assessments": [{}] if ai_enabled else [],
        "validation_decisions": [{}] if ai_enabled else [],
        **changes,
    }
    return run_id, "completed", spec, snapshot


def test_fr63_uses_a1_as_benchmark_reference_and_keeps_gate_failure_completed() -> None:
    result = compare_benchmark([_run(5, "A3"), _run(1, "A0"), _run(2, "A1"), _run(6, "A4")])
    assert result["reference_run_id"] == 2
    a3, a0, a1, a4 = result["rows"]
    assert a3["comparable"]
    assert a3["laya_devices"] == ["cuda"]
    assert a3["laya_timeouts"] == 0
    assert a3["savings"]["duration_percent"] == pytest.approx(100 / 3)
    assert a3["savings"]["tokens_percent"] == 0
    assert a0["savings"]["requests_percent"] == 100
    assert a0["savings"]["tokens_percent"] is None
    assert a1["gate"] == "failed"
    assert a1["status"] == "completed"
    assert a1["total_tokens"] == 200
    assert a1["cost_usd"] is None
    assert a4["scenario"] == "A4"
    assert not a4["comparable"]


def test_fr63_disables_savings_for_changed_coverage_and_discloses_partial_laya() -> None:
    a1 = _run(1, "A1")
    a2 = _run(2, "A2")
    a2[3]["scanner_results"][0]["coverage_records"][0]["unit_path"] = "other.java"
    a3 = _run(3, "A3", routing=[{"decision_status": "failed", "error_code": "timeout"}])
    _, changed, failed = compare_benchmark([a1, a2, a3])["rows"]
    assert not changed["comparable"]
    assert "coverage" in changed["comparison_reason"]
    assert failed["comparable"]
    assert failed["laya_devices"] == []
    assert failed["laya_timeouts"] == 1
    assert failed["limitations"]
    assert failed["savings"]["duration_percent"] == pytest.approx(100 / 3)


def test_fr63_keeps_missing_metrics_null_independently() -> None:
    a2 = _run(2, "A2", duration_seconds=None)
    a2[3]["model_calls"][1]["usage"] = {"completion_tokens": 20}
    del a2[3]["ai_usage"]["http_attempts"]
    _, row = compare_benchmark([_run(1, "A1"), a2])["rows"]
    assert row["comparable"]
    assert row["requests"] == 2
    assert row["prompt_tokens"] is None
    assert row["total_tokens"] is None
    assert row["completion_tokens"] == 40
    assert all(value is None for value in row["savings"].values())


def test_fr63_uses_transport_attempts_and_requires_same_observed_model() -> None:
    baseline = _run(1, "A1")
    baseline[3]["ai_usage"]["http_attempts"] = 4
    match = _run(2, "A2")
    another_model = _run(3, "A2")
    for call in another_model[3]["model_calls"]:
        call["model"] = "different-model"
    a1, a2, changed = compare_benchmark([baseline, match, another_model])["rows"]
    assert (a1["requests"], a1["http_attempts"]) == (2, 4)
    assert a2["savings"]["requests_percent"] == 50
    assert a2["savings"]["tokens_percent"] is None
    assert not changed["comparable"]
    assert "provider or model" in changed["comparison_reason"]


def test_fr63_reports_elapsed_stages_only_when_both_event_times_exist() -> None:
    run = _run(
        1,
        "A0",
        stages=[
            {"stage": "intake", "status": "running", "timestamp": "2026-01-02T03:04:05Z"},
            {"stage": "intake", "status": "completed", "timestamp": "2026-01-02T03:04:07Z"},
            {"stage": "laya_batch_routing", "status": "skipped"},
        ],
    )
    row = compare_benchmark([run])["rows"][0]
    assert row["stage_durations"] == [
        {"name": "intake", "status": "completed", "duration_seconds": 2.0},
        {"name": "laya_batch_routing", "status": "skipped", "duration_seconds": None},
    ]


def test_fr63_compares_observed_attempts_and_time_when_ai_falls_back() -> None:
    baseline = _run(1, "A1")
    limited = _run(
        2,
        "A2",
        final_report={"status": "partial", "ai_written": False},
        ai_usage={"requests": 0, "completed_requests": 0, "failed_requests": 0, "http_attempts": 1},
        model_calls=[],
        assessments=[{"metadata": {"error": "request budget exhausted"}}],
    )
    for run in (baseline, limited):
        run[3]["configuration"]["provider_profile"] = "test-provider"
        run[3]["configuration"]["provider_model"] = "test-model"
    _, row = compare_benchmark([baseline, limited])["rows"]
    assert row["comparable"]
    assert row["limitations"]
    assert (row["reviewed"], row["validated"]) == (0, 1)
    assert row["savings"]["requests_percent"] == 50
    assert row["savings"]["tokens_percent"] is None


def test_fr63_prefers_measured_request_cap_and_preserves_zero() -> None:
    measured = _run(1, "A1")
    configured = _run(2, "A2")
    legacy = _run(3, "A3")
    measured[3]["ai_usage"]["max_model_requests"] = 0
    measured[3]["configuration"]["max_model_requests"] = 40
    configured[3]["configuration"]["max_model_requests"] = 30
    rows = compare_benchmark([measured, configured, legacy])["rows"]
    assert [row["max_model_requests"] for row in rows] == [0, 30, None]
