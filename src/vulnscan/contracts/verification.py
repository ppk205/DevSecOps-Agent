"""VerificationObservation — một quan sát từ quy trình xác minh (ACC-06).

Khác biệt với quyết định finding cuối cùng. Cùng một quy trình đã được rà soát
được áp dụng cho cả biến thể có lỗ hổng và biến thể đã sửa, bao gồm các kiểm tra
chức năng hợp lệ và thuộc tính bảo mật xác định theo từng CWE áp dụng. Các quan sát
thực thi phân biệt rõ lỗ hổng đã được chứng minh, hành vi bị chặn, lỗi harness, và kết quả không kết luận được.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .artifact import ArtifactReference
from .enums import EvidenceKind, VerificationOutcome


class VerificationObservation(VersionedModel):
    """Kết quả của việc áp dụng một bước xác minh cho một biến thể.

    Không bao giờ trực tiếp thay đổi finding; validator tiếp nhận một tập hợp các kết
    quả này và sau đó phát ra một :class:`~vulnscan.contracts.validation.ValidationDecision`.
    """

    verification_observation_id: str = Field(
        ...,
        description="Stable identifier for this observation.",
    )
    finding_id: str = Field(
        ...,
        description="Finding this observation is evidence for.",
    )
    run_id: str = Field(
        ...,
        description="RunManifest.run_id this observation belongs to.",
    )
    procedure_version: str = Field(
        ...,
        description="Version of the reviewed verification procedure applied.",
    )
    verification_level: str = Field(
        ...,
        description="Level used: 'static', 'junit', or 'sandbox'.",
    )
    security_property: str = Field(
        ...,
        description=(
            "Observable security condition being checked for this CWE, e.g. "
            "'prepared statement used for all user-controlled SQL'."
        ),
    )
    observed_behavior: str = Field(
        ...,
        description="What was actually observed, stated neutrally.",
    )
    execution_status: VerificationOutcome = Field(
        ...,
        description=(
            "Outcome of the procedure: demonstrated, blocked, harness_failed, "
            "inconclusive, not_applicable, or not_verified."
        ),
    )
    is_vulnerable_variant: bool = Field(
        ...,
        description="True if this observation is from the vulnerable variant, False if fixed.",
    )
    legitimate_functionality_ok: bool | None = Field(
        default=None,
        description=(
            "Result of legitimate-functionality checks.  None if not run. "
            "A fixed variant passing one test does not establish general safety."
        ),
    )
    evidence_kind: EvidenceKind = Field(
        ...,
        description="Kind of evidence produced (static, runtime, structural).",
    )
    artifact_refs: list[ArtifactReference] = Field(
        default_factory=list,
        description="Artifacts produced by this verification step (JUnit XML, container logs, ...).",
    )
    evidence_strength: str = Field(
        default="none",
        description="Qualitative strength of this observation's evidence.",
    )
    observed_at: datetime = Field(
        ...,
        description="UTC timestamp when the observation was recorded.",
    )
    notes: str = Field(
        default="",
        description="Free-text notes on harness, environment, or caveats.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form observation metadata.",
    )


__all__ = ["VerificationObservation"]
