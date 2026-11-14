"""Lớp chính sách chuyển các câu trả lời khuyến nghị của Laya thành các route bước tiếp theo an toàn."""

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

# Các lane làm tiêu tốn thời gian thực của chuyên viên phân tích, vì vậy chúng phải đạt yêu cầu chứ không được phỏng đoán.
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

# Một lane chỉ được tin cậy khi model thể hiện vượt trội rõ ràng. Dưới các mức này,
# xác suất gần như ngang nhau và sự lựa chọn chỉ là nhiễu.
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
    """Trả về hai xác suất lane cao nhất, giá trị cao nhất đứng trước."""
    values = sorted((p for p in probabilities.values()), reverse=True)
    if not values:
        return None, None
    return values[0], (values[1] if len(values) > 1 else None)


class DecisionRouter:
    """Áp dụng chính sách route tất định mà không thay đổi finding status."""

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
        top, second = _top_two(answer.probabilities)
        chosen = answer.probabilities.get(selected)
        dominant = (
            top is not None
            and chosen == top
            and top >= DOMINANT_PROBABILITY
            and top - (second or 0.0) >= DOMINANT_MARGIN
        )
        if (
            review is not None
            and review.noul is not None
            and review.noul >= self.review_threshold
            or not dominant
            or selected in _SPECIALISED_LANES
            and answer.confidence < self.review_threshold
        ):
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
