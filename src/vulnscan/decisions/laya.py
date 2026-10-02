"""Lazy, failure-safe adapter for the local Laya decision model."""

from __future__ import annotations

import atexit
import importlib.util
import sys
import time
from collections.abc import Callable, Mapping
from typing import Any

from vulnscan.contracts.decision import (
    DecisionAnswer,
    DecisionQuestion,
    DecisionRequest,
    DecisionResult,
    DecisionStatus,
    DecisionType,
)
from vulnscan.core.stdio_worker import JSONWorker
from vulnscan.decisions.protocol import (
    MAX_INPUT_CHARS,
    MAX_INPUT_TOKENS,
    MODEL_ID,
    MODEL_REVISION,
)
from vulnscan.scanners.process import _cancel_check

from .state import build_evidence_state, model_state

_LOADER_TYPE = Callable[[], Any]


_process_worker = JSONWorker([sys.executable, "-m", "vulnscan.decisions.model_worker"])
atexit.register(_process_worker.close)


def _to_native_questions(questions: Mapping[str, DecisionQuestion]) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "type": question.type.value,
            "instructions": question.instructions,
            "criteria": question.criteria,
        }
        for name, question in questions.items()
    }


def _as_probability_map(value: Any) -> dict[str, float]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, float] = {}
    for key, number in value.items():
        try:
            probability = float(number)
        except (TypeError, ValueError):
            return {}
        if not 0.0 <= probability <= 1.0:
            return {}
        result[str(key)] = probability
    return result


def _parse_answer(name: str, raw: Any, question: DecisionQuestion) -> DecisionAnswer:
    if not isinstance(raw, Mapping):
        raise TypeError(f"answer {name!r} is not an object")
    answer_type = raw.get("type", question.type.value)
    if answer_type != question.type.value:
        raise ValueError(f"answer {name!r} has type {answer_type!r}")
    probabilities = _as_probability_map(raw.get("probabilities", {}))
    confidence_value = raw.get("confidence", max(probabilities.values(), default=0.0))
    try:
        confidence = float(confidence_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"answer {name!r} has invalid confidence") from exc
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"answer {name!r} has invalid confidence")

    choice = raw.get("choice")
    score = raw.get("score")
    noul = raw.get("noul")
    if question.type is DecisionType.CHOICE:
        if not isinstance(choice, str) or choice not in question.criteria:
            raise ValueError(f"answer {name!r} has invalid choice")
    elif question.type is DecisionType.SCORE:
        try:
            score = float(score) if score is not None else float("nan")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"answer {name!r} has invalid score") from exc
        if not score >= 0:
            raise ValueError(f"answer {name!r} has invalid score")
    elif question.type is DecisionType.NOUL:
        try:
            noul = float(noul) if noul is not None else float("nan")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"answer {name!r} has invalid noul") from exc
        if not 0.0 <= noul <= 1.0:
            raise ValueError(f"answer {name!r} has invalid noul")

    return DecisionAnswer(
        name=name,
        type=question.type,
        choice=choice,
        score=score,
        noul=noul,
        probabilities=probabilities,
        confidence=confidence,
        answer_confidence=raw.get("answer_confidence"),
    )


class LayaDecisionBackend:
    """Adapter around ``laya.load(...).predict(...)``.

    The adapter is intentionally injectable so unit tests never download a
    model. In production it lazy-loads the optional package once and converts
    failures into structured results.
    """

    def __init__(
        self,
        *,
        agent_loader: _LOADER_TYPE | None = None,
        model_id: str = MODEL_ID,
        model_revision: str | None = MODEL_REVISION,
        device: str = "unknown",
        max_input_chars: int = MAX_INPUT_CHARS,
        max_input_tokens: int = MAX_INPUT_TOKENS,
        timeout_seconds: float = 30,
        worker: JSONWorker | None = None,
    ) -> None:
        if max_input_chars < 1 or max_input_tokens < 1:
            raise ValueError("input limits must be positive")
        self._agent_loader = agent_loader
        self._agent: Any | None = None
        self.model_id = model_id
        self.model_revision = model_revision
        self.device = device
        self.max_input_chars = max_input_chars
        self.max_input_tokens = max_input_tokens
        self.timeout_seconds = timeout_seconds
        self.worker = worker or _process_worker

    def _load(self) -> Any:
        if self._agent is None:
            if self._agent_loader is None:
                if self.worker is _process_worker and importlib.util.find_spec("laya") is None:
                    raise ImportError("Laya optional dependency is not installed")
                raise RuntimeError("Model loading belongs to the child worker")
            self._agent = self._agent_loader()
        return self._agent

    def _failure(
        self,
        request: DecisionRequest,
        state_hash: str,
        status: DecisionStatus,
        code: str,
        message: str,
        latency_ms: float,
    ) -> DecisionResult:
        return DecisionResult(
            status=status,
            model_id=self.model_id,
            model_revision=None,
            device="unknown",
            answers={},
            latency_ms=latency_ms,
            input_truncated=False,
            state_hash=state_hash,
            question_set_version=request.question_set_version,
            error_code=code,
            error_message=message[:1_024],
        )

    def predict(self, request: DecisionRequest) -> DecisionResult:
        return self.predict_many([request])[0]

    def predict_many(self, requests: list[DecisionRequest]) -> list[DecisionResult]:
        if not requests:
            return []
        if any(request.questions != requests[0].questions for request in requests):
            raise ValueError("A batch must share one question set")
        envelopes = [
            build_evidence_state(r.state, max_chars=self.max_input_chars) for r in requests
        ]
        states = [model_state(e) for e in envelopes]
        questions = _to_native_questions(requests[0].questions)
        started = time.perf_counter()
        try:
            revision, device = self.model_revision, self.device
            if self._agent_loader is None:
                reply = self.worker.call(
                    "predict_batch",
                    {
                        "model_id": self.model_id,
                        "revision": self.model_revision,
                        "device": self.device,
                        "states": states,
                        "questions": questions,
                        "max_input_tokens": self.max_input_tokens,
                    },
                    self.timeout_seconds,
                    _cancel_check.get(),
                )
                raw_rows = reply["rows"]
                revision, device = reply["model_revision"], reply["device"]
            else:
                agent = self._load()
                device = str(getattr(agent, "device", self.device))
                if len(states) > 1 and hasattr(agent, "predict_batch"):
                    raw_rows = agent.predict_batch(states, questions, max_len=self.max_input_tokens)
                else:
                    raw_rows = [
                        agent.predict(state, questions, max_len=self.max_input_tokens)
                        for state in states
                    ]
            if not isinstance(raw_rows, list) or len(raw_rows) != len(requests):
                raise TypeError("Laya returned a mismatched batch")
        except ImportError as exc:
            return [
                self._failure(
                    r,
                    str(e["state_hash"]),
                    DecisionStatus.UNAVAILABLE,
                    "dependency_unavailable",
                    str(exc),
                    (time.perf_counter() - started) * 1000,
                )
                for r, e in zip(requests, envelopes, strict=True)
            ]
        except TimeoutError as exc:
            return [
                self._failure(
                    r,
                    str(e["state_hash"]),
                    DecisionStatus.FAILED,
                    "timeout",
                    str(exc),
                    (time.perf_counter() - started) * 1000,
                )
                for r, e in zip(requests, envelopes, strict=True)
            ]
        except Exception as exc:  # noqa: BLE001 - backend boundary must preserve baseline scan
            code = (
                "malformed_output"
                if isinstance(exc, (ValueError, TypeError, KeyError))
                else "backend_unavailable"
            )
            status = (
                DecisionStatus.INCOMPLETE
                if code == "malformed_output"
                else DecisionStatus.UNAVAILABLE
            )
            return [
                self._failure(
                    r,
                    str(e["state_hash"]),
                    status,
                    code,
                    str(exc),
                    (time.perf_counter() - started) * 1000,
                )
                for r, e in zip(requests, envelopes, strict=True)
            ]

        results: list[DecisionResult] = []
        for request, envelope, raw in zip(requests, envelopes, raw_rows, strict=True):
            try:
                if not isinstance(raw, Mapping) or not isinstance(raw.get("answers"), Mapping):
                    raise TypeError("Laya response has no answers object")
                answers = {
                    name: _parse_answer(name, raw["answers"][name], question)
                    for name, question in request.questions.items()
                }
                results.append(
                    DecisionResult(
                        status=DecisionStatus.COMPLETED,
                        model_id=self.model_id,
                        model_revision=revision,
                        device=device,
                        answers=answers,
                        latency_ms=(time.perf_counter() - started) * 1000 / len(requests),
                        input_truncated=bool(envelope["input_truncated"]),
                        state_hash=str(envelope["state_hash"]),
                        question_set_version=request.question_set_version,
                    )
                )
            except (ValueError, TypeError, KeyError) as exc:
                results.append(
                    self._failure(
                        request,
                        str(envelope["state_hash"]),
                        DecisionStatus.INCOMPLETE,
                        "malformed_output",
                        str(exc),
                        (time.perf_counter() - started) * 1000,
                    )
                )
        return results
