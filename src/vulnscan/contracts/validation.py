"""ValidationDecision and EvidenceRecord — independent validation ownership.

An AI assessment may never directly mutate a finding's status into confirmed
or rejected; only this contract can.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import (
    EvidenceKind,
    EvidenceStrength,
    FindingStatus,
    VerificationOutcome,
)


class EvidenceRecord(VersionedModel):
    """A single piece of evidence supporting or contradicting a finding."""

    evidence_id: str = Field(
        ...,
        description="Stable identifier for this evidence record.",
    )
    finding_id: str = Field(
        ...,
        description="Finding this evidence relates to.",
    )
    kind: EvidenceKind = Field(
        ...,
        description="Kind of evidence (static, runtime, structural, policy, model, documentation).",
    )
    strength: EvidenceStrength = Field(
        ...,
        description="Qualitative strength of this evidence.",
    )
    source_description: str = Field(
        ...,
        description="What this evidence is (e.g. 'Semgrep rule detection at line 42').",
    )
    artifact_ref: str | None = Field(
        default=None,
        description="Path to the artifact containing this evidence.",
    )
    source_location: str | None = Field(
        default=None,
        description="Source coordinate if applicable.",
    )
    tool: str | None = Field(
        default=None,
        description="Tool or agent that produced this evidence.",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp when this evidence was recorded.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form evidence metadata.",
    )


class ValidationDecision(VersionedModel):
    """Independent validation decision that can mutate a finding's status.

    This is the ONLY model that can move a finding to confirmed or rejected.
    An AI proposal uses :class:`Assessment`; it writes here only after
    independent verification.
    """

    decision_id: str = Field(
        ...,
        description="Stable identifier for this decision.",
    )
    finding_id: str = Field(
        ...,
        description="Finding this decision applies to.",
    )
    previous_status: FindingStatus = Field(
        ...,
        description="Finding status before this decision.",
    )
    new_status: FindingStatus = Field(
        ...,
        description="Finding status after this decision.",
    )
    outcome: VerificationOutcome = Field(
        ...,
        description="Verification outcome that produced this decision.",
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting this decision.",
    )
    evidence_strength: EvidenceStrength = Field(
        ...,
        description="Overall strength of the evidence backing this decision.",
    )
    rationale: str = Field(
        ...,
        description=(
            "Why this decision was made; must reference specific evidence. "
            "Kept separate from the finding record so the reasoning trail "
            "is preserved."
        ),
    )
    decided_by: str = Field(
        ...,
        description="Agent, user, or 'validator' that made this decision.",
    )
    decided_at: datetime = Field(
        ...,
        description="UTC timestamp of the decision.",
    )
    version: str = Field(
        default="0.1.0",
        description="Schema version of this decision record.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form decision metadata.",
    )


__all__ = ["EvidenceRecord", "ValidationDecision"]
