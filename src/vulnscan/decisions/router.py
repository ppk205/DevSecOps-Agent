"""Policy layer that turns advisory Laya answers into safe next-step routes."""

from __future__ import annotations

from typing import Any, Final

from vulnscan.contracts.decision import (
    DecisionRequest,
    DecisionResult,
    DecisionRoute,
    DecisionStatus,
)
from vulnscan.decisions.protocol import (
    FALLBACK_ROUTE,
    HIGH_CONFIDENCE_THRESHOLD,
    REVIEW_THRESHOLD,
)

_ROUTE_ANSWER = "recommended_action"

# Lanes that cost real analyst time, so they must be earned, not guessed.
_SPECIALISED_LANES = frozenset(
    {
        "fast_verification",
        "cross_file_analysis",
        "authorization_analysis",
        "jsp_context_analysis",
        "dependency_analysis",
        "secret_review",
    }
)

# A lane is only trusted when the model is clearly on top. Below these the
# probabilities are near-flat and the choice is noise.
DOMINANT_PROBABILITY: Final[float] = 0.55
DOMINANT_MARGIN: Final[float] = 0.20

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


def _top_two(probabilities: dict[str, float]) -> tuple[float | None, float | None]:
    """Return the two highest lane probabilities, highest first."""
    values = sorted((p for p in probabilities.values()), reverse=True)
    if not values:
        return None, None
    return values[0], (values[1] if len(values) > 1 else None)


class DecisionRouter:
    """Apply deterministic route policy without mutating finding status."""

    def __init__(
        self,
        *,
        high_confidence_threshold: float = HIGH_CONFIDENCE_THRESHOLD,
        review_threshold: float = REVIEW_THRESHOLD,
    ) -> None:
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
                route=FALLBACK_ROUTE,
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
        review = result.answers.get("needs_human_review")
        if (
            review is not None
            and review.noul is not None
            and review.noul >= self.review_threshold
        ):
            selected = "human_review"

        # Decide on the probability distribution, not on the model's
        # self-reported confidence. Laya's confidence can sit well below its
        # own top-1 probability, and trusting it rewrote 18 of 29 routes on the
        # T09 run: every clear low_priority was escalated to human_review,
        # which is the one lane that tells an analyst nothing.
        top_probability, runner_up = _top_two(answer.probabilities)
        dominant = (
            top_probability is not None
            and top_probability >= DOMINANT_PROBABILITY
            and (runner_up is None or top_probability - runner_up >= DOMINANT_MARGIN)
        )

        # A flat distribution is uncertainty, so nothing is trusted. Below that,
        # the specialised lanes (which cost analyst time) also need the model to
        # meet its own confidence bar. A dominant low_priority does not: if the
        # model clearly says "ignore this", second-guessing it is the very
        # escalation churn this policy exists to remove.
        if selected in _SPECIALISED_LANES or selected == "low_priority":
            untrusted = not dominant or (
                selected in _SPECIALISED_LANES and answer.confidence < self.review_threshold
            )
            if untrusted:
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
