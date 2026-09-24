"""Policy layer that turns advisory Laya answers into safe next-step routes."""

from __future__ import annotations

from typing import Any

from vulnscan.contracts.decision import (
    DecisionRequest,
    DecisionResult,
    DecisionRoute,
    DecisionStatus,
)

_ROUTE_ANSWER = "recommended_action"
_ROUTE_NAMES = {
    "fast_verification",
    "cross_file_analysis",
    "authorization_analysis",
    "jsp_context_analysis",
    "dependency_analysis",
    "secret_review",
    "human_review",
    "low_priority",
    "baseline_fallback",
}


class DecisionRouter:
    """Apply deterministic route policy without mutating finding status."""

    def __init__(self, *, high_confidence_threshold: float = 0.85, review_threshold: float = 0.60) -> None:
        if not 0.0 <= review_threshold <= high_confidence_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= review <= high <= 1")
        self.high_confidence_threshold = high_confidence_threshold
        self.review_threshold = review_threshold

    def route(
        self,
        *,
        request: DecisionRequest,
        result: DecisionResult,
        final_status: Any,
    ) -> DecisionRoute:
        if result.status is not DecisionStatus.COMPLETED:
            return DecisionRoute(
                route="baseline_fallback",
                final_status=final_status,
                affects_finding_status=False,
                model_id=result.model_id,
                model_revision=result.model_revision,
                status=result.status,
                reasons=["Laya unavailable or incomplete; deterministic baseline retained."],
                error_code=result.error_code,
            )

        answer = result.answers.get(_ROUTE_ANSWER) or result.answers.get("route")
        if answer is None:
            return DecisionRoute(
                route="human_review",
                final_status=final_status,
                affects_finding_status=False,
                model_id=result.model_id,
                model_revision=result.model_revision,
                status=result.status,
                reasons=["No routing answer was returned."],
            )

        selected = answer.choice or "human_review"
        if selected not in _ROUTE_NAMES:
            selected = "human_review"
        if answer.confidence < self.review_threshold or answer.confidence < self.high_confidence_threshold and selected in {
            "fast_verification",
            "cross_file_analysis",
            "authorization_analysis",
            "jsp_context_analysis",
            "dependency_analysis",
            "secret_review",
        }:
            selected = "human_review"

        return DecisionRoute(
            route=selected,
            confidence=answer.confidence,
            probabilities=answer.probabilities,
            final_status=final_status,
            affects_finding_status=False,
            model_id=result.model_id,
            model_revision=result.model_revision,
            status=result.status,
            reasons=["Advisory Laya route; final status remains validator-owned."],
        )
