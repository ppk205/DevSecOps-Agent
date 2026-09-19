"""ScannerResult — the envelope every scanner adapter returns.

Normalized at the boundary: adapters translate native output into this shape so
downstream modules never see vendor-specific structures.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .artifact import ArtifactReference
from .coverage import CoverageRecord
from .enums import RunStatus, ToolName
from .finding import Observation


class ScannerResult(VersionedModel):
    """Envelope returned by a scanner adapter for one tool invocation."""

    run_id: str = Field(
        ...,
        description="RunManifest.run_id this result belongs to.",
    )
    tool: ToolName = Field(
        ...,
        description="Scanner that produced this result.",
    )
    tool_version: str = Field(
        ...,
        description="Version of the scanner, e.g. '1.70.0'.",
    )
    adapter_version: str = Field(
        ...,
        description="Version of the adapter implementation that produced this envelope.",
    )
    status: RunStatus = Field(
        ...,
        description="Outcome of the tool invocation for this run.",
    )
    started_at: datetime = Field(
        ...,
        description="UTC timestamp when the tool started.",
    )
    finished_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when the tool finished; None if still running or crashed.",
    )
    observations: list[Observation] = Field(
        default_factory=list,
        description="Normalized observations emitted by this tool.",
    )
    coverage_records: list[CoverageRecord] = Field(
        default_factory=list,
        description="Per-unit coverage records produced alongside the observations.",
    )
    raw_output_refs: list[ArtifactReference] = Field(
        default_factory=list,
        description="References to raw scanner output artifacts with checksums.",
    )
    coverage_percent: float = Field(
        default=0.0,
        description="Fraction of eligible units analyzed, 0.0–100.0.",
        ge=0.0,
        le=100.0,
    )
    eligible_units: int = Field(
        default=0,
        description="Number of units in scope for this tool.",
        ge=0,
    )
    analyzed_units: int = Field(
        default=0,
        description="Number of units successfully analyzed.",
        ge=0,
    )
    skipped_units: int = Field(
        default=0,
        description="Units skipped by this tool (never counted as analyzed).",
        ge=0,
    )
    failed_units: int = Field(
        default=0,
        description="Units where the tool errored or extraction failed.",
        ge=0,
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Tool-level errors (crashes, timeouts, missing binaries).",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal warnings that may affect coverage.",
    )
    duration_ms: int | None = Field(
        default=None,
        description="Wall-clock duration of the tool invocation in milliseconds.",
        ge=0,
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific metadata preserved for traceability.",
    )

    @property
    def is_complete(self) -> bool:
        """True if the tool ran to completion without tool-level errors."""
        return self.status == RunStatus.COMPLETED and not self.errors


__all__ = ["ScannerResult"]
