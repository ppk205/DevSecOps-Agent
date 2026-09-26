"""Criteria must survive the wire round trip unchanged.

Regression guard: a score rubric is an ordinal *list*, a choice rubric is a
*dict*. Converting between them silently changed the question the model saw,
which made every real answer unparseable.
"""

from __future__ import annotations

from vulnscan.contracts.decision import DecisionType
from vulnscan.decisions.batching import _as_native_questions
from vulnscan.decisions.decision_requests import to_decision_questions
from vulnscan.decisions.triage import build_triage_questions


def test_criteria_round_trip_preserves_shape() -> None:
    original = build_triage_questions()

    rebuilt = to_decision_questions(_as_native_questions(original))

    assert set(rebuilt) == set(original)
    for name, question in original.items():
        assert rebuilt[name].criteria == question.criteria, name
        assert rebuilt[name].type is question.type
        assert rebuilt[name].instructions == question.instructions


def test_score_criteria_stays_an_ordinal_list() -> None:
    rebuilt = to_decision_questions(_as_native_questions(build_triage_questions()))

    criteria = rebuilt["evidence_sufficiency"].criteria

    assert rebuilt["evidence_sufficiency"].type is DecisionType.SCORE
    assert isinstance(criteria, list)
    assert criteria == ["insufficient", "partial", "sufficient"]


def test_choice_criteria_stays_a_mapping() -> None:
    rebuilt = to_decision_questions(_as_native_questions(build_triage_questions()))

    criteria = rebuilt["recommended_action"].criteria

    assert rebuilt["recommended_action"].type is DecisionType.CHOICE
    assert isinstance(criteria, dict)
    assert "fast_verification" in criteria


def test_ordinal_keyed_score_criteria_is_read_back_as_a_list() -> None:
    rebuilt = to_decision_questions(
        {
            "q": {
                "type": "score",
                "instructions": "how much",
                "criteria": {"0": "low", "1": "high"},
            }
        }
    )

    assert rebuilt["q"].criteria == ["low", "high"]


def test_non_ordinal_keys_are_kept_as_a_mapping() -> None:
    rebuilt = to_decision_questions(
        {
            "q": {
                "type": "score",
                "instructions": "named levels",
                "criteria": {"none": "nothing", "many": "a lot"},
            }
        }
    )

    assert rebuilt["q"].criteria == {"none": "nothing", "many": "a lot"}
