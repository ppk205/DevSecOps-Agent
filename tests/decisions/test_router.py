"""Router policy: trust the model's own lane unless it is genuinely unsure.

The router used to escalate any low-confidence ``low_priority`` to
``human_review``. That looked cautious but destroyed the model's signal: on
the T09 run it rewrote 18 of 29 routes, and the advisory layer's whole value
is knowing which lane to look at first.

Policy under test:
  * A lane chosen with a dominant top-1 probability is honoured, even when
    the self-reported confidence is below ``review_threshold``.
  * ``human_review`` is reserved for real uncertainty, not for hedging.
  * Availability and malformed answers still fall back safely.
"""

from __future__ import annotations

import pytest

from vulnscan.contracts.decision import (
    DecisionAnswer,
    DecisionQuestion,
    DecisionRequest,
    DecisionResult,
    DecisionStatus,
    DecisionType,
    FindingStatus,
)
from vulnscan.decisions.protocol import FALLBACK_ROUTE, REVIEW_THRESHOLD
from vulnscan.decisions.router import DecisionRouter

_ROUTE_NAMES = {
    "fast_verification",
    "cross_file_analysis",
    "authorization_analysis",
    "jsp_context_analysis",
    "dependency_analysis",
    "secret_review",
    "human_review",
    "low_priority",
    FALLBACK_ROUTE,
}


def _result(
    *,
    choice: str,
    confidence: float,
    probabilities: dict[str, float] | None = None,
    status: DecisionStatus = DecisionStatus.COMPLETED,
) -> DecisionResult:
    return DecisionResult(
        status=status,
        model_id="convaiinnovations/laya",
        model_revision="aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8",
        state_hash="0" * 64,
        question_set_version="laya-questions-1",
        answers={
            "recommended_action": DecisionAnswer(
                name="recommended_action",
                type=DecisionType.CHOICE,
                choice=choice,
                confidence=confidence,
                probabilities=probabilities or {choice: confidence},
            )
        },
    )


def _route(result: DecisionResult, router: DecisionRouter | None = None):
    request = DecisionRequest(
        state={"kind": "finding", "finding_id": "F1"},
        questions={
            "recommended_action": DecisionQuestion(
                name="recommended_action",
                type=DecisionType.CHOICE,
                instructions="Pick the lane a reviewer should look at first.",
            )
        },
    )
    return (router or DecisionRouter()).route(
        request=request, result=result, final_status=FindingStatus.UNPROCESSED
    )


def test_dominant_low_priority_is_not_escalated() -> None:
    """A clear low_priority must survive to the report, not be rewritten."""
    result = _result(
        choice="low_priority",
        confidence=0.52,
        probabilities={"low_priority": 0.75, "human_review": 0.02},
    )
    route = _route(result)

    assert route.route == "low_priority"
    assert route.affects_finding_status is False


def test_genuine_uncertainty_escalates_to_human_review() -> None:
    """When no lane dominates, escalate: this is what review is for."""
    result = _result(
        choice="low_priority",
        confidence=0.10,
        probabilities={"low_priority": 0.12, "human_review": 0.11},
    )
    assert _route(result).route == "human_review"


def test_specialised_lane_needs_a_confident_choice() -> None:
    """Deep-analysis lanes only earn their keep above the review threshold."""
    hesitant = _result(
        choice="cross_file_analysis",
        confidence=REVIEW_THRESHOLD - 0.05,
        probabilities={"cross_file_analysis": 0.55, "low_priority": 0.20},
    )
    assert _route(hesitant).route == "human_review"

    confident = _result(
        choice="cross_file_analysis",
        confidence=0.80,
        probabilities={"cross_file_analysis": 0.80, "low_priority": 0.10},
    )
    assert _route(confident).route == "cross_file_analysis"


def test_low_priority_is_never_upgraded_without_escalation_intent() -> None:
    """Regression: the old policy escalated on confidence alone.

    This is the behaviour that produced 18 rewrites and a 0.24 route
    accuracy on the T09 run.
    """
    result = _result(
        choice="low_priority",
        confidence=0.51,
        probabilities={"low_priority": 0.70},
    )
    assert _route(result).route == "low_priority"


def test_unavailable_backend_falls_back() -> None:
    result = _result(
        choice="low_priority",
        confidence=0.9,
        status=DecisionStatus.UNAVAILABLE,
    )
    route = _route(result)
    assert route.route == FALLBACK_ROUTE
    assert route.affects_finding_status is False


def test_missing_answer_falls_back_to_human_review() -> None:
    empty = DecisionResult(
        status=DecisionStatus.COMPLETED,
        model_id="convaiinnovations/laya",
        state_hash="0" * 64,
        question_set_version="laya-questions-1",
        answers={},
    )
    assert _route(empty).route == "human_review"


def test_unknown_lane_is_contained() -> None:
    result = _result(choice="not_a_real_lane", confidence=0.99)
    assert _route(result).route in {"human_review", FALLBACK_ROUTE}


def test_router_never_owns_finding_status() -> None:
    result = _result(choice="low_priority", confidence=0.52)
    route = _route(result)
    assert route.final_status is FindingStatus.UNPROCESSED
    assert route.affects_finding_status is False


@pytest.mark.parametrize("confidence", [0.0, 0.3, 0.59, 0.6, 0.85, 1.0])
def test_router_never_crashes_on_confidence_bounds(confidence: float) -> None:
    result = _result(choice="low_priority", confidence=confidence)
    assert _route(result).affects_finding_status is False


def test_confidence_below_threshold_still_honours_a_dominant_lane() -> None:
    """Laya's self-reported confidence can trail its own top-1 probability.

    Real payload: choice=low_priority, confidence=0.52, low_priority
    probability=0.75. The old policy escalated this on confidence alone and
    rewrote 18 of 29 routes. A clear top-1 must survive.
    """
    result = _result(
        choice="low_priority",
        confidence=REVIEW_THRESHOLD - 0.08,
        probabilities={"low_priority": 0.75, "human_review": 0.02},
    )
    assert _route(result).route == "low_priority"


def test_a_weak_top_one_still_escalates() -> None:
    """Top-1 present but barely ahead of the runner-up is not a decision."""
    result = _result(
        choice="low_priority",
        confidence=0.70,
        probabilities={"low_priority": 0.50, "human_review": 0.40},
    )
    assert _route(result).route == "human_review"


def test_probabilities_are_the_decision_input_not_confidence() -> None:
    """Same confidence, different distributions, different outcomes."""
    confident_but_flat = _result(
        choice="low_priority",
        confidence=0.75,
        probabilities={"low_priority": 0.40, "human_review": 0.38},
    )
    hesitant_but_clear = _result(
        choice="low_priority",
        confidence=0.62,
        probabilities={"low_priority": 0.80, "human_review": 0.05},
    )
    assert _route(confident_but_flat).route == "human_review"
    assert _route(hesitant_but_clear).route == "low_priority"
