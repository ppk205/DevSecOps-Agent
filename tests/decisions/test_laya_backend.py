from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from vulnscan.contracts.decision import (
    DecisionAnswer,
    DecisionQuestion,
    DecisionRequest,
    DecisionResult,
    DecisionStatus,
    DecisionType,
)
from vulnscan.decisions.laya import LayaDecisionBackend
from vulnscan.decisions.router import DecisionRouter


class FakeLaya:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def predict(self, state: dict[str, Any], questions: dict[str, Any], **kwargs: Any) -> Any:
        self.calls.append((state, questions))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _question(name: str = "route") -> DecisionQuestion:
    return DecisionQuestion(
        name=name,
        type=DecisionType.CHOICE,
        instructions="Choose the next analysis route.",
        criteria={"verify": "Run targeted verification."},
    )


def _request() -> DecisionRequest:
    return DecisionRequest(
        state={"finding_id": "f-1", "cwe_category": "CWE-89", "secret": "[REDACTED]"},
        questions={"route": _question()},
    )


def test_laya_backend_normalizes_typed_answers() -> None:
    fake = FakeLaya(
        {
            "answers": {
                "route": {
                    "type": "choice",
                    "choice": "verify",
                    "probabilities": {"verify": 0.84, "human_review": 0.16},
                    "confidence": 0.84,
                }
            }
        }
    )
    backend = LayaDecisionBackend(agent_loader=lambda: fake, model_id="test/laya")

    result = backend.predict(_request())

    assert isinstance(result, DecisionResult)
    assert result.status is DecisionStatus.COMPLETED
    assert result.model_id == "test/laya"
    assert result.answers["route"].choice == "verify"
    assert result.answers["route"].probabilities["verify"] == pytest.approx(0.84)
    assert result.input_truncated is False


def test_laya_backend_reports_unavailable_without_raising() -> None:
    backend = LayaDecisionBackend(
        agent_loader=lambda: (_ for _ in ()).throw(ImportError("no laya"))
    )

    result = backend.predict(_request())

    assert result.status is DecisionStatus.UNAVAILABLE
    assert result.error_code == "dependency_unavailable"
    assert result.answers == {}


def test_laya_backend_marks_malformed_output_incomplete() -> None:
    backend = LayaDecisionBackend(
        agent_loader=lambda: FakeLaya({"answers": {"route": {"type": "choice"}}})
    )

    result = backend.predict(_request())

    assert result.status is DecisionStatus.INCOMPLETE
    assert result.error_code == "malformed_output"
    assert result.answers == {}


def test_state_envelope_redacts_secret_values_and_is_bounded() -> None:
    state = {
        "finding_id": "f-1",
        "message": "Authorization: Bearer sk-live-123456789",
        "nested": {"api_key": "sk-live-987654321"},
        "padding": "x" * 10_000,
    }

    from vulnscan.decisions.state import build_evidence_state

    envelope = build_evidence_state(state)

    assert envelope["message"].startswith("Authorization: ")
    assert "[REDACTED]" in envelope["message"]
    assert envelope["nested"] == {"api_key": "[REDACTED]"}
    assert len(envelope["state_text"]) < 2_000
    assert envelope["input_truncated"] is True


def test_router_uses_route_and_keeps_laya_advisory() -> None:
    result = DecisionResult(
        status=DecisionStatus.COMPLETED,
        model_id="test/laya",
        model_revision=None,
        device="cpu",
        answers={
            "route": DecisionAnswer(
                name="route",
                type=DecisionType.CHOICE,
                choice="cross_file_analysis",
                probabilities={"cross_file_analysis": 0.91},
                confidence=0.91,
            )
        },
        latency_ms=4.2,
        input_truncated=False,
        state_hash="abc",
        question_set_version="questions-1",
        created_at=datetime.now(UTC),
    )

    decision = DecisionRouter().route(
        request=_request(),
        result=result,
        final_status="unresolved",
    )

    assert decision.route == "cross_file_analysis"
    assert decision.affects_finding_status is False
    assert decision.final_status == "unresolved"


def test_router_falls_back_on_unavailable() -> None:
    result = DecisionResult(
        status=DecisionStatus.UNAVAILABLE,
        model_id="test/laya",
        model_revision=None,
        device="cpu",
        answers={},
        latency_ms=0,
        input_truncated=False,
        state_hash="abc",
        question_set_version="questions-1",
        error_code="dependency_unavailable",
        created_at=datetime.now(UTC),
    )

    decision = DecisionRouter().route(
        request=_request(),
        result=result,
        final_status="unresolved",
    )

    assert decision.route == "baseline_fallback"
    assert decision.affects_finding_status is False
    assert decision.final_status == "unresolved"
