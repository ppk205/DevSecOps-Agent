"""EvaluationCase — bản ghi ca chỉ dành riêng cho evaluator (ACC-05–07).

Các nhãn dự kiến, tham chiếu biến thể đã sửa, tư cách thành viên phân chia tập dữ liệu,
và các phán đoán đánh giá CHỈ thuộc về evaluator. Scanner và agent phân tích từng biến
thể một cách độc lập; runner nhận một biến thể ẩn danh và quy trình đã được rà soát,
sau đó evaluator sẽ ghép cặp các observation.

Các bản ghi này không bao giờ được lộ ra qua các hợp đồng suy luận hoặc điểm gắn kết (mounts)
— việc chỉ ẩn chúng trong prompt là không đủ.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import (
    CWECategory,
    Severity,
    SplitMembership,
    VariantRelationship,
)


class MatchingCriteria(VersionedModel):
    """Các quy tắc để ghép cặp một ca đánh giá với một finding được tạo ra."""

    match_by_fingerprint: bool = Field(
        default=True,
        description="Match on the finding's stable fingerprint.",
    )
    match_by_location: bool = Field(
        default=True,
        description="Match on source location (file + line range).",
    )
    match_by_cwe: bool = Field(
        default=True,
        description="Match on CWE category.",
    )
    match_by_sink: bool = Field(
        default=False,
        description="Match on sink symbol or API.",
    )
    location_tolerance_lines: int = Field(
        default=0,
        description="Tolerance in lines when matching locations.",
        ge=0,
    )
    additional_rules: list[str] = Field(
        default_factory=list,
        description="Free-text extra matching rules.",
    )


class ReviewJudgment(VersionedModel):
    """Một phán đoán rà soát của con người về một trường hợp hoặc tranh chấp nhãn."""

    reviewer: str = Field(
        ...,
        description="Reviewer identity (student name or agent ID).",
    )
    reviewed_at: datetime = Field(
        ...,
        description="UTC timestamp of the review.",
    )
    judgment: str = Field(
        ...,
        description="The judgment rendered (e.g. 'agree', 'disagree', 'exclude').",
    )
    notes: str = Field(
        default="",
        description="Free-text rationale.",
    )


class EvaluationCase(VersionedModel):
    """Một ca trong tập dữ liệu đánh giá. Chỉ dành cho evaluator.

    Các case family giữ các biến thể liên quan lại với nhau; việc đổi tên hoặc
    chuyển vị trí một luồng sẽ tạo ra một biến thể hồi quy tương quan, chứ không
    phải một ví dụ nghiên cứu độc lập mới.
    """

    case_id: str = Field(
        ...,
        description="Stable case identifier.",
    )
    case_family: str = Field(
        ...,
        description=(
            "Family this case belongs to (e.g. 'servlet-sqli-ordersearch'). "
            "Related variants stay in the same family and the same split."
        ),
    )
    variant_relationship: VariantRelationship = Field(
        ...,
        description="Whether this variant is vulnerable, fixed, negative, or a regression variant.",
    )
    split: SplitMembership = Field(
        ...,
        description="Dataset split: development, held_out, evaluation, or excluded.",
    )
    expected_finding_identity: str | None = Field(
        default=None,
        description="Expected finding fingerprint or identity, if any (evaluator only).",
    )
    expected_cwe_category: CWECategory | None = Field(
        default=None,
        description="Expected CWE group for this case (evaluator only).",
    )
    expected_severity: Severity | None = Field(
        default=None,
        description="Expected reference severity (evaluator only).",
    )
    expected_labels: list[str] = Field(
        default_factory=list,
        description="All expected labels, hidden from scanners and agents.",
    )
    matching_criteria: MatchingCriteria = Field(
        default_factory=MatchingCriteria,
        description="How a produced finding is paired with this case.",
    )
    fixed_variant_refs: list[str] = Field(
        default_factory=list,
        description="References to fixed counterparts of this case (evaluator only).",
    )
    source_commit_sha: str = Field(
        ...,
        description="Commit SHA of the variant source analyzed.",
    )
    variant_path: str = Field(
        ...,
        description="Path to the variant's source tree.",
    )
    seeded_files: list[str] = Field(
        default_factory=list,
        description="Files seeded into the variant, with their origin recorded.",
    )
    review_judgments: list[ReviewJudgment] = Field(
        default_factory=list,
        description="Independent review judgments from both students.",
    )
    label_dispute: bool = Field(
        default=False,
        description="True if reviewers disagreed.  Disputed cases are excluded from scored ground truth.",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp when this case was created.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form evaluator metadata.",
    )


__all__ = ["EvaluationCase", "MatchingCriteria", "ReviewJudgment"]
