"""Bridge between the batcher's native question dicts and our contracts."""

from __future__ import annotations

from typing import Any

from vulnscan.contracts.decision import DecisionQuestion, DecisionRequest, DecisionType


def to_decision_questions(native: dict[str, dict[str, Any]]) -> dict[str, DecisionQuestion]:
    """Rebuild typed questions from the dict form the batcher passes around."""
    questions: dict[str, DecisionQuestion] = {}
    for name, raw in native.items():
        criteria = raw.get("criteria", {})
        if isinstance(criteria, list):
            # Score questions carry an ordinal rubric as a list of level labels.
            criteria = {str(index): label for index, label in enumerate(criteria)}
        questions[name] = DecisionQuestion(
            name=name,
            type=DecisionType(raw["type"]),
            instructions=str(raw.get("instructions", "")),
            criteria=criteria,
        )
    return questions


def request_from_native(
    backend: Any, state: dict[str, Any], native: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Call the backend with a typed request and return the native answer shape.

    The batcher only understands the native shape, so this keeps that single
    conversion in one place instead of duplicating it per call site.
    """
    result = backend.predict(
        DecisionRequest(
            state=state,
            questions=to_decision_questions(native),
            question_set_version="laya-questions-1",
        )
    )
    if not result.answers:
        # Preserve the failure reason so the batcher reports it honestly instead
        # of turning an unavailable model into "malformed output".
        return {"answers": {}, "__error__": result.error_code or result.status.value}
    return {
        "answers": {
            name: {
                "type": answer.type.value,
                "choice": answer.choice,
                "score": answer.score,
                "noul": answer.noul,
                "probabilities": answer.probabilities,
                "confidence": answer.confidence,
            }
            for name, answer in result.answers.items()
        }
    }
