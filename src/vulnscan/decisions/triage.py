"""Giai đoạn triage Laya ở chế độ shadow.

Giai đoạn này chạy *sau khi* bằng chứng tất định được chuẩn bị và *trước khi* phân tích
sâu có mục tiêu. Nó chỉ mang tính khuyến nghị: ghi lại một route, không bao giờ ghi finding status.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from vulnscan.contracts.decision import (
    DecisionQuestion,
    DecisionRequest,
    DecisionResult,
    DecisionRoute,
    DecisionStatus,
    DecisionType,
)
from vulnscan.contracts.enums import FindingStatus
from vulnscan.core.security import sanitize
from vulnscan.decisions.protocol import (
    INPUT_FORMAT_VERSION,
    QUESTION_SET_VERSION,
    ROUTING_POLICY_VERSION,
)

__all__ = ["QUESTION_SET_VERSION", "build_triage_questions"]

from .base import DecisionBackend
from .router import DecisionRouter

_ROUTE_CRITERIA: dict[str, str] = {
    "fast_verification": "A single targeted harness run is likely to confirm or refute this.",
    "cross_file_analysis": "The taint crosses files and needs dataflow reconstruction.",
    "authorization_analysis": "The issue depends on role or permission checks.",
    "jsp_context_analysis": "The issue depends on JSP/scriptlet or output-context analysis.",
    "dependency_analysis": "The issue is dependency or component related.",
    "secret_review": "The issue is a leaked credential and needs secret review.",
    "human_review": "Evidence is ambiguous and a human must decide.",
    "low_priority": "The finding is very unlikely to be a true positive.",
}


def build_triage_questions() -> dict[str, DecisionQuestion]:
    """Tập câu hỏi cố định được dùng cho mọi lượt chạy shadow triage."""
    return {
        "recommended_action": DecisionQuestion(
            name="recommended_action",
            type=DecisionType.CHOICE,
            instructions=(
                "You triage a normalized static-analysis finding. Choose the single next "
                "analysis step that resolves the uncertainty fastest."
            ),
            criteria=dict(_ROUTE_CRITERIA),
        ),
        "evidence_sufficiency": DecisionQuestion(
            name="evidence_sufficiency",
            type=DecisionType.SCORE,
            instructions=(
                "How sufficient is the current deterministic evidence to decide this finding "
                "without further analysis? 0 is insufficient, 2 is sufficient."
            ),
            criteria=["insufficient", "partial", "sufficient"],
        ),
        "needs_human_review": DecisionQuestion(
            name="needs_human_review",
            type=DecisionType.NOUL,
            instructions=(
                "Does this finding require a human reviewer before any status change? "
                "Answer true only when deterministic evidence is conflicting or incomplete."
            ),
        ),
    }


_EXCERPT_LIMIT = 400
_TRUNCATION_NOTE = "\n... [truncated]"


def build_excerpt(raw: Any) -> tuple[str, bool]:
    """Rút gọn đoạn trích mã thô thành snippet giới hạn, đã che dữ liệu nhạy cảm cho model.

    Laya định tuyến dựa trên văn bản này, vì vậy nó phải ngắn (đầu vào giới hạn), không chứa
    secret và được gắn cờ rõ ràng khi bị cắt. Các snippet là bằng chứng không đáng tin cậy:
    chúng mô tả finding, không bao giờ chỉ dẫn model.
    """
    text = sanitize(str(raw or "")).strip()
    if not text:
        return "", False
    truncated = len(text) > _EXCERPT_LIMIT
    if truncated:
        # Giới hạn bao gồm cả phần ghi chú, do đó đoạn trích bị cắt ngắn không bao giờ vượt quá nó.
        text = text[: _EXCERPT_LIMIT - len(_TRUNCATION_NOTE)] + _TRUNCATION_NOTE
    return text, truncated


def finding_to_state(finding: Any) -> dict[str, Any]:
    """Ánh xạ một finding vào state bị giới hạn mà Laya được phép nhìn thấy.

    Chỉ metadata do dự án kiểm soát mới được xuất: định danh, CWE, mức độ nghiêm trọng,
    nguồn gốc công cụ, tọa độ mã nguồn, cờ bằng chứng và đoạn trích mã nguồn bị giới hạn đã che dữ liệu nhạy cảm.
    Không có thông tin xác thực, không có nhãn ground-truth.
    """

    def value(item: Any) -> str:
        return str(getattr(item, "value", item) or "")

    observations = list(getattr(finding, "observations", []) or [])
    representative = observations[0] if observations else None
    tool_names = sorted(
        {value(getattr(obs, "tool", "")) for obs in observations if getattr(obs, "tool", None)}
    )
    state: dict[str, Any] = {
        "finding_id": str(getattr(finding, "finding_id", "")),
        "run_id": str(getattr(finding, "run_id", "")),
        "cwe_category": value(getattr(finding, "cwe_category", "")),
        "severity": value(getattr(finding, "severity", "")),
        "evidence_strength": value(getattr(finding, "evidence_strength", "")),
        "tool_names": tool_names,
        "observation_count": len(observations),
        "rule_ids": sorted({str(getattr(o, "rule_id", "")) for o in observations}),
    }
    location = getattr(representative, "location", None)
    if location is not None:
        state["file_path"] = str(getattr(location, "file_path", ""))
        state["line_start"] = int(getattr(location, "line_start", 0) or 0)
        state["language"] = value(getattr(location, "language", ""))
    metadata = getattr(finding, "metadata", None)
    if isinstance(metadata, dict):
        for key in ("has_dataflow", "has_sanitizer", "jsp_context", "dependency_identity"):
            if key in metadata:
                state[key] = metadata[key]
    if representative is not None:
        # Ưu tiên các đoạn trích từ adapter, dự phòng bằng mã nguồn do scan service lưu giữ.
        meta = getattr(representative, "metadata", None) or {}
        raw = meta.get("code_excerpt")
        # Semgrep CE không đăng nhập sẽ báo cáo `extra.lines` là "requires login".
        if str(raw or "").strip() in ("", "requires login"):
            raw = getattr(location, "snippet", None)
        excerpt, was_truncated = build_excerpt(raw)
        state["code_excerpt"] = excerpt
        state["excerpt_truncated"] = was_truncated
    else:
        state["code_excerpt"] = ""
        state["excerpt_truncated"] = False
    return state


@dataclass(frozen=True)
class TriageOutcome:
    """Kết quả khuyến nghị cho một finding; không mang thẩm quyền quyết định trạng thái."""

    finding_id: str
    route: DecisionRoute
    result: DecisionResult
    state_hash: str
    question_set_version: str = QUESTION_SET_VERSION

    @property
    def available(self) -> bool:
        return self.result.status is DecisionStatus.COMPLETED

    def as_artifact_payload(self) -> dict[str, Any]:
        """Payload bằng chứng tất định, con người đọc được cho artifact store."""
        return {
            "finding_id": self.finding_id,
            "route": self.route.route,
            "route_confidence": self.route.confidence,
            "route_probabilities": dict(self.route.probabilities),
            "decision_status": self.result.status.value,
            "model_id": self.result.model_id,
            "model_revision": self.result.model_revision,
            "device": self.result.device,
            "latency_ms": round(self.result.latency_ms, 3),
            "input_truncated": self.result.input_truncated,
            "state_hash": self.state_hash,
            "question_set_version": self.question_set_version,
            "input_format_version": INPUT_FORMAT_VERSION,
            "routing_policy_version": ROUTING_POLICY_VERSION,
            "affects_finding_status": self.route.affects_finding_status,
            "final_status": str(self.route.final_status or ""),
            "reasons": list(self.route.reasons),
            "error_code": self.result.error_code,
            "answers": {
                name: {
                    "type": answer.type.value,
                    "choice": answer.choice,
                    "score": answer.score,
                    "noul": answer.noul,
                    "confidence": answer.confidence,
                    "answer_confidence": answer.answer_confidence,
                    "probabilities": dict(answer.probabilities),
                }
                for name, answer in self.result.answers.items()
            },
        }


class LayaTriageStage:
    """Chạy định tuyến Laya khuyến nghị trên các finding mà không can thiệp vào trạng thái cuối cùng."""

    def __init__(
        self,
        backend: DecisionBackend,
        *,
        router: DecisionRouter | None = None,
        enabled: bool = False,
        questions: dict[str, DecisionQuestion] | None = None,
    ) -> None:
        self.backend = backend
        self.router = router or DecisionRouter()
        self.enabled = enabled
        self.questions = questions or build_triage_questions()

    def _request(self, finding: Any) -> DecisionRequest:
        return DecisionRequest(
            state=finding_to_state(finding),
            questions=self.questions,
            question_set_version=QUESTION_SET_VERSION,
        )

    def triage_one(self, finding: Any) -> TriageOutcome:
        request = self._request(finding)
        finding_id = str(request.state.get("finding_id", ""))
        final_status = getattr(finding, "status", FindingStatus.UNRESOLVED)

        if not self.enabled:
            result = DecisionResult(
                status=DecisionStatus.UNAVAILABLE,
                model_id="none",
                answers={},
                state_hash="",
                question_set_version=QUESTION_SET_VERSION,
                error_code="disabled",
            )
        else:
            result = self.backend.predict(request)

        route = self.router.route(request=request, result=result, final_status=final_status)
        return TriageOutcome(
            finding_id=finding_id,
            route=route,
            result=result,
            state_hash=result.state_hash,
        )

    def triage_many(self, findings: Sequence[Any]) -> list[TriageOutcome]:
        return [self.triage_one(finding) for finding in findings]
