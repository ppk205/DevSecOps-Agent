"""Typed contracts for advisory decision backends such as Laya.

Decision contracts are deliberately separate from provider/chat contracts.
They carry probabilities and routing recommendations only; they never own a
finding's final status or a CVSS vector.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import FindingStatus


class DecisionType(str, Enum):
    """Question types supported by the Laya decision protocol."""

    CHOICE = "choice"
    SCORE = "score"
    NOUL = "noul"


class DecisionStatus(str, Enum):
    """Lifecycle of a decision-backend invocation."""

    COMPLETED = "completed"
    UNAVAILABLE = "unavailable"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class DecisionQuestion(VersionedModel):
    """One typed question sent to a decision backend."""

    name: str = Field(..., min_length=1, max_length=128)
    type: DecisionType
    instructions: str = Field(..., min_length=1, max_length=4_096)
    criteria: dict[str, str] | list[str] = Field(default_factory=dict)


class DecisionRequest(VersionedModel):
    """Bounded, normalized evidence and questions for a decision backend."""

    state: dict[str, Any]
    questions: dict[str, DecisionQuestion]
    question_set_version: str = Field(default="laya-questions-1", min_length=1)
    model_policy: dict[str, Any] = Field(default_factory=dict)


class DecisionAnswer(VersionedModel):
    """Typed answer returned by a decision backend."""

    name: str
    type: DecisionType
    choice: str | None = None
    score: float | None = Field(default=None, ge=0.0)
    noul: float | None = Field(default=None, ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)
    confidence: float = Field(..., ge=0.0, le=1.0)
    answer_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class DecisionResult(VersionedModel):
    """Structured result and operational metadata for one decision call."""

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
    """Advisory route and its explicit status-ownership boundary."""

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
