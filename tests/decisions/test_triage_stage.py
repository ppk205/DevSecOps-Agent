"""Shadow-mode triage stage tests.

The backend is faked; no model is ever loaded here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from vulnscan.contracts.enums import (
    CWECategory,
    EvidenceStrength,
    FindingStatus,
    LanguageKind,
    Severity,
    ToolName,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.decisions.triage import (
    QUESTION_SET_VERSION,
    LayaTriageStage,
    build_triage_questions,
    finding_to_state,
)

_ROUTE_ANSWER = {
    "recommended_action": {
        "type": "choice",
        "choice": "cross_file_analysis",
        "probabilities": {"cross_file_analysis": 0.93, "human_review": 0.07},
        "confidence": 0.93,
    },
    "evidence_sufficiency": {
        "type": "score",
        "score": 0.4,
        "probabilities": {"0": 0.5, "1": 0.4, "2": 0.1},
        "confidence": 0.5,
    },
    "needs_human_review": {"type": "noul", "noul": 0.22, "confidence": 0.78},
}


class RecordingBackend:
    def __init__(self, raw_answers: dict[str, Any] | None = None, error: Any = None) -> None:
        self.raw_answers = raw_answers or {}
        self.error = error
        self.requests: list[Any] = []

    def predict(self, request: Any) -> Any:
        from vulnscan.decisions.laya import LayaDecisionBackend

        self.requests.append(request)
        if self.error is not None:
            return LayaDecisionBackend(
                agent_loader=lambda: (_ for _ in ()).throw(self.error)
            ).predict(request)

        # Reuse the real parser so the stage is tested against the shipped contract.
        return LayaDecisionBackend(
            agent_loader=lambda: _EchoAgent(self.raw_answers),
            model_id="test/laya",
            model_revision="rev-1",
            device="cuda:0",
        ).predict(request)


class _EchoAgent:
    """Minimal stand-in exposing the same shape as ``laya.Agent.predict``."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers

    def predict(self, state: Any, questions: Any, **kwargs: Any) -> Any:
        return {"answers": self.answers}


def _finding(status: FindingStatus = FindingStatus.UNPROCESSED) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id="F-1",
        run_id="R-1",
        fingerprint="fp-1",
        title="Possible SQL injection",
        cwe_category=CWECategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=status,
        observations=[
            Observation(
                observation_id="O-1",
                run_id="R-1",
                tool=ToolName.SEMGREP,
                tool_version="1.70.0",
                rule_id="java/sql-injection",
                cwe_category=CWECategory.SQL_INJECTION,
                severity=Severity.HIGH,
                message="String-concatenated SQL query",
                location=SourceCoordinate(
                    file_path="src/main/java/com/x/Dao.java",
                    language=LanguageKind.JAVA,
                    line_start=42,
                ),
                detected_at=now,
            )
        ],
        evidence_strength=EvidenceStrength.MODERATE,
        metadata={"has_dataflow": True, "jsp_context": False},
        created_at=now,
        updated_at=now,
    )


def test_triage_questions_are_frozen_and_typed() -> None:
    questions = build_triage_questions()

    assert set(questions) == {
        "recommended_action",
        "evidence_sufficiency",
        "needs_human_review",
    }
    assert questions["recommended_action"].type.value == "choice"
    assert questions["evidence_sufficiency"].type.value == "score"
    assert questions["needs_human_review"].type.value == "noul"


def test_finding_state_exposes_only_bounded_metadata() -> None:
    state = finding_to_state(_finding())

    assert state["finding_id"] == "F-1"
    assert state["file_path"] == "src/main/java/com/x/Dao.java"
    assert state["line_start"] == 42
    assert state["has_dataflow"] is True
    assert "snippet" not in state
    assert "locations" not in state


def test_disabled_stage_skips_backend_and_keeps_baseline() -> None:
    backend = RecordingBackend()
    stage = LayaTriageStage(backend, enabled=False)

    outcome = stage.triage_one(_finding())

    assert backend.requests == []
    assert outcome.route.route == "baseline_fallback"
    assert outcome.route.affects_finding_status is False
    assert outcome.available is False
    assert outcome.result.error_code == "disabled"


def test_shadow_triage_routes_without_changing_status() -> None:
    backend = RecordingBackend(_ROUTE_ANSWER)
    stage = LayaTriageStage(backend, enabled=True)

    finding = _finding(status=FindingStatus.PENDING_VALIDATION)
    outcome = stage.triage_one(finding)

    assert outcome.available is True
    assert outcome.route.route == "cross_file_analysis"
    assert outcome.route.affects_finding_status is False
    assert outcome.route.final_status is FindingStatus.PENDING_VALIDATION
    assert finding.status is FindingStatus.PENDING_VALIDATION


def test_triage_artifact_payload_is_json_ready_and_advisory() -> None:
    backend = RecordingBackend(_ROUTE_ANSWER)
    stage = LayaTriageStage(backend, enabled=True)

    payload = stage.triage_one(_finding()).as_artifact_payload()

    assert payload["route"] == "cross_file_analysis"
    assert payload["model_revision"] == "rev-1"
    assert payload["affects_finding_status"] is False
    assert payload["question_set_version"] == QUESTION_SET_VERSION
    assert payload["answers"]["recommended_action"]["choice"] == "cross_file_analysis"
    assert payload["answers"]["needs_human_review"]["noul"] == pytest.approx(0.22)


def test_triage_many_returns_one_outcome_per_finding() -> None:
    backend = RecordingBackend(_ROUTE_ANSWER)
    stage = LayaTriageStage(backend, enabled=True)

    outcomes = stage.triage_many([_finding(), _finding()])

    assert len(outcomes) == 2
    assert len(backend.requests) == 2
