"""The experiment harness must grade against truth, never against itself."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnscan.evaluation.laya_experiments import (
    GroundTruthRow,
    evaluate_from_files,
    evaluate_routing,
    load_ground_truth,
)


def _payload(
    finding_id: str,
    route: str,
    confidence: float = 0.8,
    status: str = "completed",
    cwe: str = "CWE-89",
    language: str = "java",
):
    return {
        "finding_id": finding_id,
        "route": route,
        "decision_status": status,
        "cwe": cwe,
        "language": language,
        "model_id": "convaiinnovations/laya",
        "model_revision": "aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8",
        "answers": {
            "recommended_action": {"type": "choice", "choice": route, "confidence": confidence}
        },
    }


def _truth(finding_id: str, expected, cwe="CWE-89", language="java") -> GroundTruthRow:
    return GroundTruthRow(
        finding_id=finding_id, expected_route=expected, cwe=cwe, language=language
    )


def test_correct_routes_produce_perfect_calibration() -> None:
    result = evaluate_routing(
        [_payload("F1", "human_review", 1.0), _payload("F2", "low_priority", 1.0)],
        [_truth("F1", True), _truth("F2", False)],
    )

    assert result["routing"]["route_accuracy"] == 1.0
    assert result["calibration"]["ece"] == pytest.approx(0.0, abs=1e-6)
    assert result["calibration"]["n"] == 2


def test_wrong_routes_drive_ece_up() -> None:
    result = evaluate_routing(
        [_payload("F1", "low_priority", 1.0), _payload("F2", "low_priority", 1.0)],
        [_truth("F1", True), _truth("F2", False)],
    )

    assert result["routing"]["route_accuracy"] == 0.5
    assert result["routing"]["missed_escalations"] == 1
    # Half the graded routes were wrong at full confidence.
    assert result["calibration"]["ece"] == pytest.approx(0.5, abs=1e-6)


def test_confident_but_wrong_is_the_costliest_failure() -> None:
    result = evaluate_routing([_payload("F1", "low_priority", 1.0)], [_truth("F1", True)])

    assert result["calibration"]["ece"] == pytest.approx(1.0, abs=1e-6)
    assert result["calibration"]["brier"] == pytest.approx(1.0, abs=1e-6)


def test_unavailable_decisions_are_excluded_from_calibration() -> None:
    payloads = [
        _payload("F1", "human_review", 0.9, status="unavailable"),
        _payload("F2", "human_review", 0.9),
    ]

    result = evaluate_routing(payloads, [_truth("F1", True), _truth("F2", True)])

    assert result["routing"]["unavailable"] == 1
    assert result["calibration"]["n"] == 1


def test_payloads_without_ground_truth_are_still_counted() -> None:
    result = evaluate_routing([_payload("F1", "human_review")], [])

    assert result["graded"] == 1
    assert result["ground_truth_matched"] == 0
    assert result["routing"]["scored_routes"] == 0
    # Zero scored routes is unknown accuracy, not 0% accuracy.
    assert result["routing"]["route_accuracy"] is None
    assert result["routing"]["false_escalation_rate"] is None


def test_report_declares_advisory_only_and_status_owner() -> None:
    result = evaluate_routing([_payload("F1", "human_review")], [_truth("F1", True)])

    protocol = result["protocol"]
    assert protocol["advisory_only"] is True
    assert protocol["status_owner"] == "IndependentValidator"


def test_breakdowns_carry_cwe_and_language() -> None:
    result = evaluate_routing(
        [
            _payload("F1", "human_review"),
            _payload("F2", "human_review", cwe="CWE-79", language="jsp"),
        ],
        [_truth("F1", True), _truth("F2", True, cwe="CWE-79", language="jsp")],
    )

    assert result["routing"]["by_cwe"]["CWE-89"]["n"] == 1
    assert result["routing"]["by_language"]["jsp"]["n"] == 1


def test_error_codes_are_surfaced_with_their_meaning() -> None:
    payload = _payload("F1", "baseline_fallback", status="unavailable")
    payload["error_code"] = "package_missing"

    result = evaluate_routing([payload], [_truth("F1", True)])

    assert result["error_codes_seen"] == ["package_missing"]
    assert "not installed" in result["known_error_codes"]["package_missing"]


def test_ground_truth_file_accepts_object_or_bare_list(tmp_path: Path) -> None:
    rows = [{"finding_id": "F1", "expected_route": True, "cwe": "CWE-89", "language": "java"}]

    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"rows": rows}), encoding="utf-8")
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(rows), encoding="utf-8")

    assert load_ground_truth(wrapped)[0].finding_id == "F1"
    assert load_ground_truth(bare)[0].expected_route is True


def test_evaluate_from_files_reads_the_advisory_block(tmp_path: Path) -> None:
    scan = tmp_path / "scan.json"
    scan.write_text(
        json.dumps({"advisory_routing": {"payloads": [_payload("F1", "human_review")]}}),
        encoding="utf-8",
    )
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps([{"finding_id": "F1", "expected_route": True}]), encoding="utf-8")

    result = evaluate_from_files(scan, truth)

    assert result["graded"] == 1
    assert result["routing"]["route_accuracy"] == 1.0
