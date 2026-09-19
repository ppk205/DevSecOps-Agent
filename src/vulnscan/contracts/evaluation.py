"""EvaluationCase — evaluator-only case record (ACC-05–07).

Expected labels, fixed-variant references, split membership, and evaluation
judgments belong ONLY to the evaluator.  Scanners and agents analyze each
variant independently; the runner receives an opaque variant and reviewed
procedure, and the evaluator pairs observations afterwards.

These records must never be exposed through the inference contracts or mounts
— hiding them only in prompts is insufficient.
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
    """Rules for pairing an evaluation case with a produced finding."""

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
    """One human review judgment on a case or label dispute."""

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
    """One case in the evaluation dataset.  Evaluator-only.

    Case families keep related variants together; renaming or relocating a
    flow creates a correlated regression variant, not a new independent
    research example.
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
