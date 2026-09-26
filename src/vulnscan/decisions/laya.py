"""Lazy, failure-safe adapter for the local Laya decision model."""

from __future__ import annotations

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
from vulnscan.decisions.protocol import (
    MAX_INPUT_CHARS,
    MAX_INPUT_TOKENS,
    MODEL_ID,
)

from .state import build_evidence_state

_LOADER_TYPE = Callable[[], Any]


def _default_loader() -> Any:
    try:
        import laya
    except ImportError as exc:  # pragma: no cover - exercised with injected loader
        raise ImportError("Laya optional dependency is not installed") from exc
    return laya.load(MODEL_ID)


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
            score = float(score)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"answer {name!r} has invalid score") from exc
        if score < 0:
            raise ValueError(f"answer {name!r} has invalid score")
    elif question.type is DecisionType.NOUL:
        try:
            noul = float(noul)
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
        model_revision: str | None = None,
        device: str = "unknown",
        max_input_chars: int = MAX_INPUT_CHARS,
        max_input_tokens: int = MAX_INPUT_TOKENS,
    ) -> None:
        if max_input_chars < 1 or max_input_tokens < 1:
            raise ValueError("input limits must be positive")
        self._agent_loader = agent_loader or _default_loader
        self._agent: Any | None = None
        self.model_id = model_id
        self.model_revision = model_revision
        self.device = device
        self.max_input_chars = max_input_chars
        self.max_input_tokens = max_input_tokens

    def _load(self) -> Any:
        if self._agent is None:
            self._agent = self._agent_loader()
        return self._agent

    @staticmethod
    def _failure(
        request: DecisionRequest,
        state_hash: str,
        status: DecisionStatus,
        code: str,
        message: str,
        latency_ms: float,
    ) -> DecisionResult:
        return DecisionResult(
            status=status,
            model_id=MODEL_ID,
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
        envelope = build_evidence_state(request.state, max_chars=self.max_input_chars)
        state_payload = {
            key: value
            for key, value in envelope.items()
            if key not in {"state_text", "state_hash", "input_truncated"}
        }
        state_hash = str(envelope["state_hash"])
        started = time.perf_counter()
        try:
            agent = self._load()
            raw = agent.predict(
                state_payload,
                _to_native_questions(request.questions),
                max_len=self.max_input_tokens,
            )
            if not isinstance(raw, Mapping) or not isinstance(raw.get("answers"), Mapping):
                raise TypeError("Laya response has no answers object")
            answers: dict[str, DecisionAnswer] = {}
            for name, question in request.questions.items():
                if name not in raw["answers"]:
                    raise ValueError(f"missing answer {name!r}")
                answers[name] = _parse_answer(name, raw["answers"][name], question)
        except ImportError as exc:
            latency_ms = (time.perf_counter() - started) * 1_000
            return self._failure(request, state_hash, DecisionStatus.UNAVAILABLE, "dependency_unavailable", str(exc), latency_ms)
        except TimeoutError as exc:
            latency_ms = (time.perf_counter() - started) * 1_000
            return self._failure(request, state_hash, DecisionStatus.FAILED, "timeout", str(exc), latency_ms)
        except (ValueError, TypeError, KeyError) as exc:
            latency_ms = (time.perf_counter() - started) * 1_000
            return self._failure(request, state_hash, DecisionStatus.INCOMPLETE, "malformed_output", str(exc), latency_ms)
        except Exception as exc:  # noqa: BLE001 - backend boundary must preserve baseline scan
            latency_ms = (time.perf_counter() - started) * 1_000
            return self._failure(request, state_hash, DecisionStatus.UNAVAILABLE, "backend_unavailable", str(exc), latency_ms)

        return DecisionResult(
            status=DecisionStatus.COMPLETED,
            model_id=self.model_id,
            model_revision=self.model_revision,
            device=self.device,
            answers=answers,
            latency_ms=(time.perf_counter() - started) * 1_000,
            input_truncated=bool(envelope["input_truncated"]),
            state_hash=state_hash,
            question_set_version=request.question_set_version,
        )
