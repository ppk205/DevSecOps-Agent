"""Assessment — the AI-proposed conclusion for a finding (never mutates status).

The bounded agent or non-agentic model writes one of these per finding.  It is
a *proposal*: only :class:`~vulnscan.contracts.validation.ValidationDecision`
may move a finding to confirmed or rejected.  CVSS v4.0 vectors are recorded
verbatim and validated independently.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import CWECategory, EvidenceStrength, Severity, VerificationOutcome


class CVSSAssessment(VersionedModel):
    """CVSS v4.0 scoring payload for a finding.

    Only officially-defined vectors are stored; no numeric equivalents are
    invented for native scanner severities.
    """

    vector: str = Field(
        ...,
        description=(
            "CVSS v4.0 vector string, e.g. "
            "'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H'. "
            "Malformed vectors are rejected before persistence."
        ),
        pattern=r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NPQ]/PR:[NLH]/UI:[NP]/VC:[HLN]",
    )
    version: str = Field(
        default="4.0",
        description="CVSS specification version used, e.g. '4.0'.",
    )
    base_score: float | None = Field(
        default=None,
        description="Base score in [0.0, 10.0] if computed.",
        ge=0.0,
        le=10.0,
    )
    qualitative: Severity | None = Field(
        default=None,
        description="Severity bucket derived from the base score.",
    )
    source: str = Field(
        default="ai-proposal",
        description="Who produced the vector ('ai-proposal', 'manual', 'validator').",
    )
    notes: str = Field(
        default="",
        description="Rationale for metric choices (e.g. why PR:L).",
    )


class Assessment(VersionedModel):
    """Proposed assessment for one finding, produced by a provider-backed model.

    ``proposed_status`` is advisory only; the finding's real status changes
    only through validation.
    """

    assessment_id: str = Field(
        ...,
        description="Stable identifier for this assessment.",
    )
    finding_id: str = Field(
        ...,
        description="Finding this assessment proposes a conclusion for.",
    )
    run_id: str = Field(
        ...,
        description="RunManifest.run_id this assessment belongs to.",
    )
    proposed_status: str = Field(
        ...,
        description=(
            "Advisory conclusion the model proposes (e.g. 'confirmed', "
            "'rejected', 'unresolved').  It cannot directly mutate the finding."
        ),
    )
    proposed_severity: Severity = Field(
        default=Severity.UNDETERMINED,
        description="Severity the model proposes, if any.",
    )
    cwe_category: CWECategory | None = Field(
        default=None,
        description="CWE group the model judges applicable, if any.",
    )
    cvss: CVSSAssessment | None = Field(
        default=None,
        description="CVSS v4.0 vector and score proposal.",
    )
    confidence: float = Field(
        default=0.0,
        description="Model-reported confidence in its proposal, [0.0, 1.0].",
        ge=0.0,
        le=1.0,
    )
    assumptions: list[str] = Field(
        default_factory=list,
        description=(
            "Every assumption the proposal depends on (e.g. 'attacker can "
            "reach /order/search unauthenticated').  Each must be checkable."
        ),
    )
    rationale: str = Field(
        ...,
        description="Reasoning for the proposal, referencing evidence by ID.",
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="EvidenceRecord IDs supporting the proposal.",
    )
    evidence_strength: EvidenceStrength = Field(
        default=EvidenceStrength.NONE,
        description="Strength of evidence the model judged available.",
    )
    validation_outcome: VerificationOutcome | None = Field(
        default=None,
        description="Outcome of independent validation, filled in later; None until then.",
    )
    validation_decision_id: str | None = Field(
        default=None,
        description="ID of the ValidationDecision that resolved this assessment, if any.",
    )
    model_id: str = Field(
        ...,
        description="Provider model identifier used, e.g. 'gpt-4o'.",
    )
    model_version: str = Field(
        ...,
        description="Version of the model or model settings snapshot.",
    )
    provider_id: str = Field(
        ...,
        description="ProviderProfile.id used for this assessment.",
    )
    context_evidence_id: str | None = Field(
        default=None,
        description="ContextEvidence.id consulted for this proposal, if any.",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp when the assessment was written.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form assessment metadata.",
    )


__all__ = ["Assessment", "CVSSAssessment"]
