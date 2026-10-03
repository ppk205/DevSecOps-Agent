"""Calibration and routing metrics are graded against evaluator truth only."""

from __future__ import annotations

import pytest

from vulnscan.evaluation.calibration import (
    build_routing_report,
    compute_calibration,
    reliability_diagram,
)


def test_confident_and_correct_has_only_the_binning_gap() -> None:
    # Predicted 0.95, observed 1.0: the whole 0.05 gap is miscalibration.
    result = compute_calibration([0.95] * 10, [True] * 10)

    assert result.n == 10
    assert result.ece == pytest.approx(0.05, abs=1e-9)
    assert result.accuracy == 1.0


def test_zero_confidence_on_correct_item_is_miscalibrated() -> None:
    # Predicted 0.1, observed 1.0: gap 0.9 in ECE, (0.1-1)^2 in Brier.
    result = compute_calibration([0.1] * 10, [True] * 10)

    assert result.ece == pytest.approx(0.9, abs=1e-9)
    assert result.brier == pytest.approx(0.81, abs=1e-9)


def test_half_confident_random_model_has_zero_ece() -> None:
    # Predicted 0.5, observed 0.5 is exactly what a calibrated coin looks like:
    # ECE is 0 while Brier still shows the weak discrimination.
    result = compute_calibration([0.5] * 100, [True] * 50 + [False] * 50)

    assert result.ece == pytest.approx(0.0, abs=1e-6)
    assert result.brier == pytest.approx(0.25)
    assert result.accuracy == pytest.approx(0.5)


def test_maximally_overconfident_model_has_ece_one() -> None:
    result = compute_calibration([1.0] * 10, [False] * 10)

    assert result.ece == pytest.approx(1.0)
    assert result.brier == pytest.approx(1.0)


def test_brier_matches_manual_computation() -> None:
    result = compute_calibration([0.8, 0.3], [True, False])

    expected = (0.8 - 1) ** 2 + 0.3**2
    assert result.brier == pytest.approx(expected / 2)


def test_empty_input_is_not_an_error() -> None:
    result = compute_calibration([], [])

    assert (result.n, result.ece, result.brier) == (0, 0.0, 0.0)
    # An ungraded series must serialise as unknown, not as a measured zero.
    assert result.to_dict()["ece"] is None
    assert result.to_dict()["brier"] is None
    assert result.to_dict()["accuracy"] is None


def test_mismatched_lengths_are_rejected() -> None:
    with pytest.raises(ValueError, match="same length"):
        compute_calibration([0.5], [True, False])


def test_confidence_one_lands_in_the_last_bin() -> None:
    diagram = reliability_diagram([1.0], [True])

    assert len(diagram) == 1
    assert diagram[0]["hi"] == 1.0
    assert diagram[0]["count"] == 1


def test_diagram_bins_sum_to_total() -> None:
    confidences = [0.05, 0.15, 0.45, 0.55, 0.95, 1.0]
    diagram = reliability_diagram(confidences, [True, False, True, True, False, True])

    assert sum(b["count"] for b in diagram) == len(confidences)


def _row(route: str, cwe: str = "CWE-89", language: str = "java", expected=None) -> dict:
    row = {"route": route, "cwe": cwe, "language": language, "decision_status": "completed"}
    if expected is not None:
        row["expected_route"] = expected
    return row


def test_correct_escalation_scores_as_accurate() -> None:
    report = build_routing_report([_row("human_review", expected=True)])

    assert report.scored_routes == 1
    assert report.correct_routes == 1
    assert report.route_accuracy == 1.0
    assert report.false_escalation_rate == 0.0


def test_missed_escalation_is_counted_separately() -> None:
    report = build_routing_report([_row("low_priority", expected=True)])

    assert report.correct_routes == 0
    assert report.missed_escalations == 1
    assert report.false_escalations == 0
    assert report.false_escalation_rate == 0.0


def test_expected_route_can_name_a_specific_lane() -> None:
    report = build_routing_report([_row("cross_file_analysis", expected="cross_file_analysis")])

    assert report.route_accuracy == 1.0


def test_rows_without_expectations_are_counted_but_not_scored() -> None:
    report = build_routing_report([_row("low_priority")])

    assert report.total == 1
    assert report.scored_routes == 0
    # Nothing was graded, so accuracy is unknown rather than 0%.
    assert report.route_accuracy is None


def test_unavailable_decisions_are_tracked() -> None:
    row = _row("baseline_fallback")
    row["decision_status"] = "unavailable"

    report = build_routing_report([row])

    assert report.unavailable == 1


def test_breakdowns_are_reported_per_cwe_and_language() -> None:
    report = build_routing_report(
        [
            _row("human_review", cwe="CWE-89", expected=True),
            _row("low_priority", cwe="CWE-89", expected=True),
            _row("human_review", cwe="CWE-79", language="jsp", expected=True),
        ]
    )

    assert report.by_cwe["CWE-89"] == {"n": 2, "correct": 1, "accuracy": 0.5}
    assert report.by_cwe["CWE-79"]["accuracy"] == 1.0
    assert report.by_language["java"]["n"] == 2
    assert report.by_language["jsp"]["n"] == 1


def test_route_counts_are_ordered_by_frequency() -> None:
    report = build_routing_report(
        [_row("low_priority"), _row("low_priority"), _row("human_review")]
    )

    assert list(report.to_dict()["route_counts"]) == ["low_priority", "human_review"]
