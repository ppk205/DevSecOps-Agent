"""Observation, Finding, and FindingGroup — the core detection and consolidation models.

Deduplication is conservative: location, weakness, and source/sink evidence
must all match.  Observations are never merged solely because CWE labels match;
all contributing observations are preserved on the resulting Finding.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import (
    CWECategory,
    EvidenceStrength,
    FindingStatus,
    LanguageKind,
    Severity,
    ToolName,
)


class SourceCoordinate(VersionedModel):
    """A location in source code, robust across normalization and export."""

    file_path: str = Field(
        ...,
        description="Repository-relative path to the source file.",
    )
    language: LanguageKind = Field(
        default=LanguageKind.JAVA,
        description="Language of this source file.",
    )
    line_start: int = Field(
        ...,
        description="1-based starting line number.",
        ge=1,
    )
    line_end: int | None = Field(
        default=None,
        description="1-based ending line number (inclusive).",
        ge=1,
    )
    column_start: int | None = Field(
        default=None,
        description="1-based starting column.",
        ge=1,
    )
    column_end: int | None = Field(
        default=None,
        description="1-based ending column.",
        ge=1,
    )
    symbol: str | None = Field(
        default=None,
        description="Class, method, or JSP expression at this location.",
    )
    snippet: str | None = Field(
        default=None,
        description="Small source snippet for display (kept short).",
    )

    def as_string(self) -> str:
        """Canonical one-line form, e.g. 'Foo.java:42:10'."""
        out = f"{self.file_path}:{self.line_start}"
        if self.column_start is not None:
            out += f":{self.column_start}"
        return out


class Observation(VersionedModel):
    """One raw finding as emitted by a single scanner.

    Observations are immutable once persisted; consolidation works on copies.
    """

    observation_id: str = Field(
        ...,
        description="Stable identifier unique within a run.",
    )
    run_id: str = Field(
        ...,
        description="RunManifest.run_id that produced this observation.",
    )
    tool: ToolName = Field(
        ...,
        description="Scanner that emitted this observation.",
    )
    tool_version: str = Field(
        ...,
        description="Version of the scanner.",
    )
    rule_id: str = Field(
        ...,
        description="Native rule identifier, e.g. 'java/sql-injection', 'FINDSECBUGS_SQL_INJECTION_JPA'.",
    )
    rule_pack_version: str | None = Field(
        default=None,
        description="Version of the rule pack or query pack used.",
    )
    cwe_category: CWECategory | None = Field(
        default=None,
        description="Mapped CWE group; None if the tool did not name one.",
    )
    severity: Severity = Field(
        default=Severity.UNDETERMINED,
        description="Severity mapped onto reference categories; numeric CVSS is never invented for it.",
    )
    native_severity: str | None = Field(
        default=None,
        description="Original severity string from the tool, preserved verbatim.",
    )
    message: str = Field(
        ...,
        description="Tool-reported message for this observation.",
    )
    confidence: float = Field(
        default=1.0,
        description="Tool-reported confidence in [0.0, 1.0].",
        ge=0.0,
        le=1.0,
    )
    location: SourceCoordinate = Field(
        ...,
        description="Location of the observation in source.",
    )
    dependency_identity: str | None = Field(
        default=None,
        description="For dependency findings: 'group:artifact:version' or CPE/PURL.",
    )
    raw_output_ref: str | None = Field(
        default=None,
        description="Path to the raw scanner output artifact.",
    )
    detected_at: datetime = Field(
        ...,
        description="UTC timestamp when the observation was recorded.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific extra fields, preserved for traceability.",
    )

    def fingerprint(self) -> str:
        """Stable per-observation identity: tool + rule + location + dependency."""
        return f"{self.tool.value}|{self.rule_id}|{self.location.as_string()}|{self.dependency_identity or ''}"


class FindingGroup(VersionedModel):
    """A group of observations consolidated into one finding.

    Grouping requires matching location, weakness, and source/sink evidence —
    never CWE labels alone.
    """

    group_id: str = Field(
        ...,
        description="Stable identifier for this group.",
    )
    finding_id: str = Field(
        ...,
        description="Finding this group belongs to.",
    )
    tool_names: list[ToolName] = Field(
        default_factory=list,
        description="Distinct tools contributing observations to this group.",
    )
    observation_ids: list[str] = Field(
        default_factory=list,
        description="IDs of all observations in this group; preserved even after consolidation.",
    )
    representative_observation_id: str | None = Field(
        default=None,
        description="Observation chosen to represent the group in reports.",
    )
    grouping_rationale: str = Field(
        ...,
        description="Why these observations were grouped (must cite location/weakness/sink evidence).",
    )
    grouping_method: str = Field(
        default="conservative_location_weakness_sink",
        description="Algorithm that produced the group.",
    )
    grouped_at: datetime = Field(
        ...,
        description="UTC timestamp when grouping happened.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form grouping metadata.",
    )


class Finding(VersionedModel):
    """A consolidated, human-visible finding.

    ``status`` moves only via :class:`~vulnscan.contracts.validation.ValidationDecision`;
    an AI assessment may not write CONFIRMED or REJECTED directly.
    """

    finding_id: str = Field(
        ...,
        description="Stable identifier unique within a run.",
    )
    run_id: str = Field(
        ...,
        description="RunManifest.run_id that produced this finding.",
    )
    fingerprint: str = Field(
        ...,
        description=(
            "Stable identity hash over location, weakness, and source/sink "
            "evidence.  Two findings with the same fingerprint are the same "
            "issue across runs."
        ),
    )
    title: str = Field(
        ...,
        description="Short human-readable title.",
    )
    description: str = Field(
        default="",
        description="Longer description of the suspected weakness.",
    )
    cwe_category: CWECategory = Field(
        ...,
        description="Primary CWE group for this finding.",
    )
    additional_cwe_labels: list[CWECategory] = Field(
        default_factory=list,
        description="Secondary CWE labels; never merged solely because labels match.",
    )
    severity: Severity = Field(
        default=Severity.UNDETERMINED,
        description="Current severity classification (assessment may update it).",
    )
    status: FindingStatus = Field(
        default=FindingStatus.UNPROCESSED,
        description="Workflow status; CONFIRMED/REJECTED only via validation decisions.",
    )
    observations: list[Observation] = Field(
        default_factory=list,
        description="All contributing observations.",
    )
    groups: list[FindingGroup] = Field(
        default_factory=list,
        description="Observation groups inside this finding.",
    )
    evidence_strength: EvidenceStrength = Field(
        default=EvidenceStrength.NONE,
        description="Strength of evidence currently backing this finding.",
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="IDs of EvidenceRecords attached to this finding.",
    )
    created_at: datetime = Field(
        ...,
        description="UTC timestamp when the finding was created.",
    )
    updated_at: datetime = Field(
        ...,
        description="UTC timestamp of the last modification.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form finding metadata.",
    )


__all__ = ["Finding", "FindingGroup", "Observation", "SourceCoordinate"]
