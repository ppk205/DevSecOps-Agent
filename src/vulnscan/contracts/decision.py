"""Hợp đồng định kiểu (typed contracts) cho các decision backend tham vấn như Laya.

Các hợp đồng quyết định được cố ý tách biệt khỏi các hợp đồng provider/chat.
Chúng chỉ mang theo xác suất và đề xuất định tuyến; chúng không bao giờ sở hữu
trạng thái cuối cùng của finding hoặc vector CVSS.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import FindingStatus


class DecisionType(str, Enum):
    """Các loại câu hỏi được hỗ trợ bởi giao thức quyết định Laya."""

    CHOICE = "choice"
    SCORE = "score"
    NOUL = "noul"


class DecisionStatus(str, Enum):
    """Vòng đời của một lần gọi decision-backend."""

    COMPLETED = "completed"
    UNAVAILABLE = "unavailable"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class DecisionQuestion(VersionedModel):
    """Một câu hỏi được định kiểu gửi tới một decision backend."""

    name: str = Field(..., min_length=1, max_length=128)
    type: DecisionType
    instructions: str = Field(..., min_length=1, max_length=4_096)
    criteria: dict[str, str] | list[str] = Field(default_factory=dict)


class DecisionRequest(VersionedModel):
    """Bằng chứng và câu hỏi có giới hạn, đã được chuẩn hóa cho một decision backend."""

    state: dict[str, Any]
    questions: dict[str, DecisionQuestion]
    question_set_version: str = Field(default="laya-questions-1", min_length=1)
    model_policy: dict[str, Any] = Field(default_factory=dict)


class DecisionAnswer(VersionedModel):
    """Câu trả lời được định kiểu trả về bởi một decision backend."""

    name: str
    type: DecisionType
    choice: str | None = None
    score: float | None = Field(default=None, ge=0.0)
    noul: float | None = Field(default=None, ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)
    confidence: float = Field(..., ge=0.0, le=1.0)
    answer_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class DecisionResult(VersionedModel):
    """Kết quả có cấu trúc và metadata hoạt động cho một lệnh gọi quyết định."""

    status: DecisionStatus
    model_id: str
    model_revision: str | None = None
    device: str = "unknown"
    answers: dict[str, DecisionAnswer] = Field(default_factory=dict)
    latency_ms: float = Field(default=0.0, ge=0.0)
    input_truncated: bool = False
    state_hash: str
    question_set_version: str
    error_code: str | None = None
    error_message: str | None = Field(default=None, max_length=1_024)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DecisionRoute(VersionedModel):
    """Tuyến tham vấn và ranh giới sở hữu trạng thái tường minh của nó."""

    route: str = Field(..., min_length=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)
    final_status: FindingStatus | None = None
    affects_finding_status: bool = False
    model_id: str | None = None
    model_revision: str | None = None
    status: DecisionStatus
    reasons: list[str] = Field(default_factory=list)
    error_code: str | None = None
