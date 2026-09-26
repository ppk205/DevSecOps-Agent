"""Cache and batch-routing tests for the advisory Laya stage."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from vulnscan.contracts.decision import DecisionRequest
from vulnscan.contracts.enums import (
    CWECategory,
    EvidenceStrength,
    FindingStatus,
    LanguageKind,
    Severity,
    ToolName,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.decisions.batching import DecisionCache, triage_many_batched
from vulnscan.decisions.triage import build_triage_questions


class BatchAgent:
    def __init__(self) -> None:
        self.batch_calls: list[list[dict[str, Any]]] = []
        self.single_calls = 0

    def predict_batch(self, states: list[Any], questions: Any, **kwargs: Any) -> list[Any]:
        self.batch_calls.append(list(states))
        return [{"answers": _answers(state["finding_id"])} for state in states]

    def predict(self, state: Any, questions: Any, **kwargs: Any) -> Any:
        self.single_calls += 1
        return {"answers": _answers(state["finding_id"])}


def _answers(finding_id: str) -> dict[str, Any]:
    return {
        "recommended_action": {
            "type": "choice",
            "choice": "fast_verification",
            "probabilities": {"fast_verification": 0.88, "human_review": 0.12},
            "confidence": 0.88,
        },
        "evidence_sufficiency": {
            "type": "score",
            "score": 1.0,
            "probabilities": {"0": 0.2, "1": 0.6, "2": 0.2},
            "confidence": 0.6,
        },
        "needs_human_review": {"type": "noul", "noul": 0.1, "confidence": 0.9},
    }


def _finding(finding_id: str) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id=finding_id,
        run_id="R-1",
        fingerprint=f"fp-{finding_id}",
        title="Possible injection",
        cwe_category=CWECategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=FindingStatus.UNPROCESSED,
        observations=[
            Observation(
                observation_id=f"O-{finding_id}",
                run_id="R-1",
                tool=ToolName.SEMGREP,
                tool_version="1.70.0",
                rule_id="java/sql-injection",
                cwe_category=CWECategory.SQL_INJECTION,
                severity=Severity.HIGH,
                message="Concatenated query",
                location=SourceCoordinate(
                    file_path=f"src/{finding_id}.java",
                    language=LanguageKind.JAVA,
                    line_start=10,
                ),
                detected_at=now,
            )
        ],
        evidence_strength=EvidenceStrength.MODERATE,
        created_at=now,
        updated_at=now,
    )


def test_batched_routing_preserves_order_and_status() -> None:
    agent = BatchAgent()
    findings = [_finding(f"F-{i}") for i in range(3)]

    outcomes = triage_many_batched(findings, agent, build_triage_questions(), batch_size=2)

    assert [o.finding_id for o in outcomes] == ["F-0", "F-1", "F-2"]
    assert all(o.route.route == "fast_verification" for o in outcomes)
    assert all(o.route.affects_finding_status is False for o in outcomes)
    assert all(o.route.final_status is FindingStatus.UNPROCESSED for o in outcomes)
    # 3 findings at batch_size=2 -> 2 batched calls, 0 single-state calls
    assert len(agent.batch_calls) == 2
    assert agent.single_calls == 0


def test_cache_avoids_repeated_inference_for_identical_state() -> None:
    agent = BatchAgent()
    cache = DecisionCache()
    questions = build_triage_questions()
    findings = [_finding("F-1"), _finding("F-1")]

    first = triage_many_batched(findings, agent, questions, cache=cache, batch_size=4)
    second = triage_many_batched(findings, agent, questions, cache=cache, batch_size=4)

    assert len(first) == 2
    assert [o.route.route for o in first] == [o.route.route for o in second]
    assert len(cache) == 1
    assert cache.hits == 2


def test_cache_key_depends_on_question_set() -> None:
    cache = DecisionCache()
    request = DecisionRequest(state={"a": 1}, questions=build_triage_questions())
    other = DecisionRequest(
        state={"a": 1},
        questions={"only_one": build_triage_questions()["needs_human_review"]},
    )

    assert cache.key(request) != cache.key(other)


def test_batching_falls_back_when_batch_api_fails() -> None:
    class BrokenBatch(BatchAgent):
        def predict_batch(self, states: list[Any], questions: Any, **kwargs: Any) -> list[Any]:
            raise RuntimeError("CUDA OOM")

    agent = BrokenBatch()
    findings = [_finding("F-0"), _finding("F-1")]

    outcomes = triage_many_batched(findings, agent, build_triage_questions(), batch_size=4)

    assert [o.finding_id for o in outcomes] == ["F-0", "F-1"]
    assert agent.single_calls == 2


def test_invalid_batch_size_is_rejected() -> None:
    with pytest.raises(ValueError, match="batch_size"):
        triage_many_batched([], BatchAgent(), build_triage_questions(), batch_size=0)
