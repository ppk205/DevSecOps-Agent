"""Rebuild typed questions from the dict form used on the wire.

The batcher passes questions around as plain dicts, so this module is the one
place that converts them back into the typed contract.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vulnscan.contracts.decision import DecisionQuestion, DecisionType


def _criteria_from_native(qtype: DecisionType, criteria: Any) -> dict[str, str] | list[str]:
    """Restore the original criteria shape.

    A score rubric is an *ordinal list* of level labels, while a choice rubric
    is a dict of ``value -> description``. The dict form is ambiguous on the
    wire, so an ordinal-keyed dict is read back as the list it came from;
    otherwise a round trip would silently change the question the model sees.
    """
    if isinstance(criteria, list):
        return [str(item) for item in criteria]
    if not isinstance(criteria, Mapping):
        return {}
    ordinal = sorted(criteria) == [str(i) for i in range(len(criteria))]
    if qtype is DecisionType.SCORE and ordinal:
        return [str(criteria[key]) for key in sorted(criteria, key=int)]
    return {str(key): str(value) for key, value in criteria.items()}


def to_decision_questions(native: dict[str, dict[str, Any]]) -> dict[str, DecisionQuestion]:
    """Rebuild typed questions from the dict form the batcher passes around."""
    questions: dict[str, DecisionQuestion] = {}
    for name, raw in native.items():
        qtype = DecisionType(raw["type"])
        questions[name] = DecisionQuestion(
            name=name,
            type=qtype,
            instructions=str(raw.get("instructions", "")),
            criteria=_criteria_from_native(qtype, raw.get("criteria", {})),
        )
    return questions
