"""ReportExport and SARIFReport — report contracts shared by backend, UI, and evaluator.

Exports SARIF 2.1.0, JSON, and human-readable HTML/Markdown.  Confirmed,
rejected, unresolved, and unprocessed counts are kept distinct everywhere.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .artifact import ArtifactReference
from .enums import ExportFormat, Severity


class FindingCounts(VersionedModel):
    """Count buckets that must stay distinct in every report."""

    total: int = Field(default=0, description="All findings.", ge=0)
    confirmed: int = Field(default=0, description="Validated as real.", ge=0)
    rejected: int = Field(default=0, description="Validated as not real.", ge=0)
    unresolved: int = Field(default=0, description="Evidence could not support a conclusion.", ge=0)
    unprocessed: int = Field(default=0, description="Not yet triaged or assessed.", ge=0)

    def validate_counts(self) -> bool:
        """True if the status buckets partition the total."""
        return self.confirmed + self.rejected + self.unresolved + self.unprocessed == self.total


class ReportExport(VersionedModel):
    """One exported report artifact with its summary metadata."""

    export_id: str = Field(
        ...,
        description="Stable identifier for this export.",
    )
    run_id: str = Field(
        ...,
        description="RunManifest.run_id this report describes.",
    )
    format: ExportFormat = Field(
        ...,
        description="Export format: sarif, json, html, or markdown.",
    )
    artifact_ref: ArtifactReference = Field(
        ...,
        description="Reference to the generated report file (path + checksum).",
    )
    counts: FindingCounts = Field(
        default_factory=FindingCounts,
        description="Finding counts by status; buckets must stay distinct.",
    )
    coverage_summary: dict[str, Any] = Field(
        default_factory=dict,
        description="Coverage limitations surfaced in the report (ACC-07).",
    )
    generated_at: datetime = Field(
        ...,
        description="UTC timestamp when the export was generated.",
    )
    generated_by: str = Field(
        default="system",
        description="Who triggered the export (user, cli, api, scheduler).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form export metadata.",
    )

    def validate_consistency(self) -> bool:
        """True if internal consistency checks pass."""
        return self.counts.validate_counts()


class SarifLocation(VersionedModel):
    """A SARIF 2.1.0 physical location."""

    file_path: str = Field(..., description="Repository-relative file path.")
    line_start: int | None = Field(default=None, description="1-based start line.", ge=1)
    line_end: int | None = Field(default=None, description="1-based end line.", ge=1)
    column_start: int | None = Field(default=None, description="1-based start column.", ge=1)
    column_end: int | None = Field(default=None, description="1-based end column.", ge=1)
    snippet: str | None = Field(default=None, description="Source snippet shown in the viewer.")


class SarifResult(VersionedModel):
    """One SARIF 2.1.0 result entry."""

    rule_id: str = Field(..., description="Rule identifier.")
    rule_name: str | None = Field(default=None, description="Human-readable rule name.")
    cwe_category: str | None = Field(default=None, description="CWE label, e.g. 'CWE-89'.")
    severity: Severity = Field(
        default=Severity.UNDETERMINED,
        description="Severity bucket mapped to SARIF level.",
    )
    message: str = Field(..., description="Result message.")
    locations: list[SarifLocation] = Field(
        default_factory=list,
        description="Physical locations of the result.",
    )
    finding_id: str = Field(..., description="Finding ID for traceability.")
    partial_fingerprints: dict[str, str] = Field(
        default_factory=dict,
        description="Fingerprints for result identity.",
    )


class SarifReport(VersionedModel):
    """SARIF 2.1.0 log-file envelope.

    Field names mirror the SARIF spec so the serialized object can be written
    to disk with minimal transformation.
    """

    version: str = Field(
        default="2.1.0",
        description="SARIF schema version.",
    )
    schema_uri: str = Field(
        default="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        alias="$schema",
        description="SARIF schema URI.  Serialized as '$schema' via to_sarif_dict().",
    )
    run_id: str = Field(..., description="RunManifest.run_id this SARIF describes.")
    generated_at: datetime = Field(..., description="UTC generation timestamp.")
    tool_name: str = Field(..., description="Producing tool name, e.g. 'devsecops-agent'.")
    tool_version: str = Field(..., description="Producing tool version.")
    results: list[SarifResult] = Field(default_factory=list, description="All reported results.")
    artifact_refs: list[ArtifactReference] = Field(
        default_factory=list,
        description="Artifacts referenced by this report.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Extra SARIF properties kept under properties.",
    )


__all__ = [
    "FindingCounts",
    "ReportExport",
    "SarifLocation",
    "SarifReport",
    "SarifResult",
]
