"""Caching and batch helpers for the advisory Laya stage.

Speed comes from two places only: skip identical states entirely, and evaluate
many findings in a single model forward pass. Neither changes what the baseline
pipeline already decided.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

from vulnscan.contracts.decision import (
    DecisionQuestion,
    DecisionRequest,
    DecisionResult,
    DecisionStatus,
)
from vulnscan.contracts.enums import FindingStatus

from .router import DecisionRouter
from .state import build_evidence_state
from .triage import QUESTION_SET_VERSION, TriageOutcome, finding_to_state

_LOGGER = logging.getLogger(__name__)


def question_signature(questions: dict[str, DecisionQuestion]) -> str:
    """Stable signature of the question set; part of the cache key."""
    return json.dumps(
        {
            name: {
                "type": question.type.value,
                "instructions": question.instructions,
                "criteria": question.criteria,
            }
            for name, question in sorted(questions.items())
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class DecisionCache:
    """In-memory cache keyed by redacted state hash + question signature."""

    def __init__(self) -> None:
        self._entries: dict[str, DecisionResult] = {}
        self.hits = 0
        self.misses = 0

    def key(self, request: DecisionRequest) -> str:
        state_hash = build_evidence_state(request.state)["state_hash"]
        return f"{request.question_set_version}|{question_signature(request.questions)}|{state_hash}"

    def get(self, request: DecisionRequest) -> DecisionResult | None:
        cached = self._entries.get(self.key(request))
        if cached is None:
            self.misses += 1
            return None
        self.hits += 1
        return cached

    def put(self, request: DecisionRequest, result: DecisionResult) -> None:
        if result.status is DecisionStatus.COMPLETED:
            self._entries[self.key(request)] = result

    def __len__(self) -> int:
        return len(self._entries)


def _as_native_questions(questions: dict[str, DecisionQuestion]) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "type": question.type.value,
            "instructions": question.instructions,
            "criteria": question.criteria,
        }
        for name, question in questions.items()
    }


def _to_request(state: dict[str, Any], questions: dict[str, DecisionQuestion]) -> DecisionRequest:
    return DecisionRequest(
        state=state,
        questions=questions,
        question_set_version=QUESTION_SET_VERSION,
    )


def triage_many_batched(
    findings: Sequence[Any],
    agent: Any,
    questions: dict[str, DecisionQuestion],
    *,
    router: DecisionRouter | None = None,
    batch_size: int = 4,
    cache: DecisionCache | None = None,
    max_input_tokens: int = 512,
) -> list[TriageOutcome]:
    """Route many findings using batched inference plus a per-state cache.

    ``agent`` is any object exposing ``predict(state, questions, **kwargs)`` or
    ``predict_batch(states, questions, **kwargs)``; both shapes are supported so
    the stage works against the real ``laya.Agent`` and against fakes.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    policy = router or DecisionRouter()
    outcomes: list[TriageOutcome | None] = [None] * len(findings)

    pending: list[int] = []
    requests: dict[int, DecisionRequest] = {}
    for index, finding in enumerate(findings):
        request = _to_request(finding_to_state(finding), questions)
        requests[index] = request
        cached = cache.get(request) if cache is not None else None
        if cached is not None:
            outcomes[index] = _outcome(finding, request, cached, policy)
        else:
            pending.append(index)

    for start in range(0, len(pending), batch_size):
        chunk = pending[start : start + batch_size]
        results = _run_chunk(agent, chunk, requests, max_input_tokens)
        for index, result in zip(chunk, results, strict=True):
            if cache is not None:
                cache.put(requests[index], result)
            outcomes[index] = _outcome(findings[index], requests[index], result, policy)

    return [outcome for outcome in outcomes if outcome is not None]


def _run_chunk(
    agent: Any,
    chunk: Sequence[int],
    requests: dict[int, DecisionRequest],
    max_input_tokens: int,
) -> list[DecisionResult]:
    from .laya import LayaDecisionBackend

    states = [requests[index].state for index in chunk]
    first = requests[chunk[0]]
    native = _as_native_questions(first.questions)

    if hasattr(agent, "predict_batch"):
        try:
            raw = agent.predict_batch(states, native, max_len=max_input_tokens)
            if isinstance(raw, Sequence) and len(raw) == len(chunk):
                return [
                    _parse(row, requests[index], first.questions) for index, row in zip(chunk, raw, strict=True)
                ]
        except Exception:
            # Batch inference is an optimisation only: a failure must not lose the
            # findings, so the stage falls back to per-state inference below.
            _LOGGER.warning(
                "Laya batch inference failed; falling back to single-state calls",
                exc_info=True,
            )

    backend = LayaDecisionBackend(agent_loader=lambda: agent, max_input_tokens=max_input_tokens)
    return [backend.predict(requests[index]) for index in chunk]


def _parse(raw: Any, request: DecisionRequest, questions: dict[str, DecisionQuestion]) -> DecisionResult:
    from .laya import _parse_answer

    if not isinstance(raw, dict) or not isinstance(raw.get("answers"), dict):
        return DecisionResult(
            status=DecisionStatus.INCOMPLETE,
            model_id="laya",
            answers={},
            state_hash="",
            question_set_version=request.question_set_version,
            error_code="malformed_output",
        )
    answers = {}
    try:
        for name, question in questions.items():
            answers[name] = _parse_answer(name, raw["answers"][name], question)
    except (TypeError, ValueError, KeyError) as exc:
        return DecisionResult(
            status=DecisionStatus.INCOMPLETE,
            model_id="laya",
            answers={},
            state_hash="",
            question_set_version=request.question_set_version,
            error_code="malformed_output",
            error_message=str(exc)[:1_024],
        )
    return DecisionResult(
        status=DecisionStatus.COMPLETED,
        model_id="laya",
        answers=answers,
        state_hash="",
        question_set_version=request.question_set_version,
    )


def _outcome(
    finding: Any,
    request: DecisionRequest,
    result: DecisionResult,
    router: DecisionRouter,
) -> TriageOutcome:
    final_status = getattr(finding, "status", FindingStatus.UNPROCESSED)
    route = router.route(request=request, result=result, final_status=final_status)
    return TriageOutcome(
        finding_id=str(request.state.get("finding_id", "")),
        route=route,
        result=result,
        state_hash=result.state_hash,
    )
