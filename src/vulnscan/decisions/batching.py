"""Các helper lưu bộ nhớ đệm và xử lý theo lô cho giai đoạn Laya tham vấn.

Tốc độ chỉ đến từ hai điểm: bỏ qua hoàn toàn các trạng thái giống nhau, và đánh
giá nhiều finding trong một lượt lan truyền xuôi của mô hình. Cả hai
đều không làm thay đổi những gì pipeline cơ sở đã quyết định.
"""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from vulnscan.contracts.decision import (
    DecisionQuestion,
    DecisionRequest,
    DecisionResult,
    DecisionStatus,
)
from vulnscan.contracts.enums import FindingStatus
from vulnscan.decisions.protocol import (
    INPUT_FORMAT_VERSION,
    MAX_INPUT_CHARS,
    MAX_INPUT_TOKENS,
)

from .router import DecisionRouter
from .state import build_evidence_state, model_state
from .triage import QUESTION_SET_VERSION, TriageOutcome, finding_to_state

_LOGGER = logging.getLogger(__name__)


def question_signature(questions: dict[str, DecisionQuestion]) -> str:
    """Chữ ký ổn định của tập câu hỏi; là một phần của khóa cache."""
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
    """Bộ nhớ đệm trong bộ nhớ (in-memory cache) có khóa là hash trạng thái đã biên tập + chữ ký câu hỏi."""

    def __init__(self) -> None:
        self._entries: dict[str, DecisionResult] = {}
        self.hits = 0
        self.misses = 0

    def key(self, request: DecisionRequest) -> str:
        max_chars = int(request.model_policy.get("max_input_chars") or MAX_INPUT_CHARS)
        state_hash = build_evidence_state(request.state, max_chars=max_chars)["state_hash"]
        return (
            f"{INPUT_FORMAT_VERSION}|{json.dumps(request.model_policy, sort_keys=True)}|"
            f"{request.question_set_version}|{question_signature(request.questions)}|{state_hash}"
        )

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
    max_input_tokens: int = MAX_INPUT_TOKENS,
    on_batch: Callable[[int, int, list[DecisionResult]], None] | None = None,
) -> list[TriageOutcome]:
    """Định tuyến nhiều finding bằng cách sử dụng suy luận theo lô kết hợp bộ nhớ đệm theo trạng thái.

    ``agent`` là bất kỳ đối tượng nào cung cấp ``predict(state, questions, **kwargs)`` hoặc
    ``predict_batch(states, questions, **kwargs)``; cả hai dạng đều được hỗ trợ để giai
    đoạn này hoạt động với ``laya.Agent`` thực tế cũng như với các fake object.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be >= 1")
    policy = router or DecisionRouter()
    outcomes: list[TriageOutcome | None] = [None] * len(findings)

    pending: list[int] = []
    requests: dict[int, DecisionRequest] = {}
    for index, finding in enumerate(findings):
        request = _to_request(finding_to_state(finding), questions)
        request.model_policy = {
            key: getattr(agent, key, None)
            for key in ("model_id", "model_revision", "max_input_tokens", "max_input_chars")
        }
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
        if on_batch is not None:
            processed = len(findings) - len(pending) + start + len(chunk)
            on_batch(processed, len(findings), results)

    return [outcome for outcome in outcomes if outcome is not None]


def _looks_like_backend(candidate: Any) -> bool:
    """True khi *candidate* đã trả về một :class:`DecisionResult` được định kiểu.

    Một ``laya.Agent`` thô cũng có ``predict``, nhưng nó nhận ``(state, questions)``
    và trả về một dict, do đó một backend thực sự được phân biệt bằng kiểu trả về đã khai
    báo của nó. Duck-typing giúp điều này hoạt động cho cả các test double.
    """
    if not callable(getattr(candidate, "predict", None)):
        return False
    try:
        return_type = inspect.signature(candidate.predict).return_annotation
    except (TypeError, ValueError):
        return False
    return "DecisionResult" in str(return_type)


def _run_chunk(
    agent: Any,
    chunk: Sequence[int],
    requests: dict[int, DecisionRequest],
    max_input_tokens: int,
) -> list[DecisionResult]:
    from .laya import LayaDecisionBackend

    if isinstance(agent, LayaDecisionBackend):
        return agent.predict_many([requests[index] for index in chunk])

    # Một backend thực sự đã tuân theo hợp đồng của chúng ta, vì vậy kết quả định kiểu của nó được sử dụng
    # nguyên trạng mà không cần truyền tải qua mạng. Cố ý sử dụng duck-typing: DecisionBackend là một
    # Protocol không thể kiểm tra lúc runtime, và một test fake cũng phải được chấp nhận.
    if _looks_like_backend(agent):
        return [agent.predict(requests[index]) for index in chunk]

    states = [model_state(build_evidence_state(requests[index].state)) for index in chunk]
    first = requests[chunk[0]]
    native = _as_native_questions(first.questions)

    if hasattr(agent, "predict_batch"):
        try:
            raw = agent.predict_batch(states, native, max_len=max_input_tokens)
            if isinstance(raw, Sequence) and len(raw) == len(chunk):
                return [
                    _parse(row, requests[index], first.questions)
                    for index, row in zip(chunk, raw, strict=True)
                ]
        except Exception:
            # Suy luận theo lô chỉ là một tối ưu hóa: sự cố không được làm mất các
            # finding, vì vậy giai đoạn này sẽ chuyển sang suy luận theo từng trạng thái bên dưới.
            _LOGGER.warning(
                "Laya batch inference failed; falling back to single-state calls",
                exc_info=True,
            )

    backend = LayaDecisionBackend(agent_loader=lambda: agent, max_input_tokens=max_input_tokens)
    return [backend.predict(requests[index]) for index in chunk]


def _parse(
    raw: Any, request: DecisionRequest, questions: dict[str, DecisionQuestion]
) -> DecisionResult:
    from .laya import _parse_answer

    envelope = build_evidence_state(request.state)

    if not isinstance(raw, Mapping) or not isinstance(raw.get("answers"), Mapping):
        # Một backend đã báo cáo lỗi có cấu trúc sẽ giữ nguyên lý do của chính nó.
        reason = raw.get("__error__") if isinstance(raw, Mapping) else None
        return DecisionResult(
            status=DecisionStatus.UNAVAILABLE if reason else DecisionStatus.INCOMPLETE,
            model_id="laya",
            answers={},
            state_hash=str(envelope["state_hash"]),
            question_set_version=request.question_set_version,
            error_code=str(reason or "malformed_output"),
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
            state_hash=str(envelope["state_hash"]),
            question_set_version=request.question_set_version,
            error_code="malformed_output",
            error_message=str(exc)[:1_024],
        )
    return DecisionResult(
        status=DecisionStatus.COMPLETED,
        model_id="laya",
        answers=answers,
        state_hash=str(envelope["state_hash"]),
        input_truncated=bool(envelope["input_truncated"]),
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
