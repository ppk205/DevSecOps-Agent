"""RunManifest — full provenance and reproducibility record for one scan run.

Records input hashes, tool versions, model settings, timings, usage, failures,
and artifact checksums.  Interrupted stages are recorded explicitly and
retried as new attempts while previous artifacts are retained.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .artifact import ArtifactReference
from .enums import RunStatus, StageStatus, ToolName
from .provider import ProviderUsage
from .scan_spec import ScanSpecification


class StageTiming(VersionedModel):
    """Timing and outcome of one pipeline stage."""

    stage_name: str = Field(
        ...,
        description="Stage identifier, e.g. 'intake', 'scan:semgrep', 'normalize', 'assess', 'validate'.",
    )
    status: StageStatus = Field(
        ...,
        description="Outcome of this stage attempt.",
    )
    attempt: int = Field(
        default=1,
        description="Attempt number; interrupted stages retry as new attempts.",
        ge=1,
    )
    started_at: datetime = Field(
        ...,
        description="UTC timestamp when this attempt started.",
    )
    finished_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when this attempt finished; None if interrupted.",
    )
    duration_ms: int | None = Field(
        default=None,
        description="Wall-clock duration in milliseconds.",
        ge=0,
    )
    error: str | None = Field(
        default=None,
        description="Error message if this attempt failed.",
    )
    artifact_refs: list[ArtifactReference] = Field(
        default_factory=list,
        description="Artifacts produced by this stage attempt.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form stage metadata.",
    )


class ToolVersionRecord(VersionedModel):
    """Version of a tool or container used during the run."""

    tool: ToolName = Field(
        ...,
        description="Scanner or tool this version record describes.",
    )
    tool_version: str = Field(
        ...,
        description="Reported version string, e.g. '1.70.0'.",
    )
    container_image: str | None = Field(
        default=None,
        description="Container image used to run this tool, if any.",
    )
    container_digest: str | None = Field(
        default=None,
        description="Container image digest (sha256) if a container was used.",
    )
    rules_pack_version: str | None = Field(
        default=None,
        description="Version of the rule pack or query pack used.",
    )
    path: str | None = Field(
        default=None,
        description="Path or command used to invoke the tool.",
    )


class ModelSettings(VersionedModel):
    """Snapshot of model settings used for a run (frozen before evaluation)."""

    model_id: str = Field(
        ...,
        description="Provider model identifier, e.g. 'gpt-4o'.",
    )
    provider_id: str = Field(
        ...,
        description="ProviderProfile.id used.",
    )
    temperature: float | None = Field(
        default=None,
        description="Sampling temperature, if set.",
    )
    max_tokens: int | None = Field(
        default=None,
        description="Maximum tokens per response.",
        ge=1,
    )
    system_prompt_version: str | None = Field(
        default=None,
        description="Version of the system prompt used.",
    )
    agent_config_version: str | None = Field(
        default=None,
        description="Version of the bounded-agent configuration.",
    )
    context_profile: str | None = Field(
        default=None,
        description="Context profile applied for this run.",
    )
    settings_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Complete settings snapshot for reproducibility.",
    )


class RunManifest(VersionedModel):
    """Complete provenance record for one scan run.

    Persisted at run start and updated as stages complete; the final manifest
    is what makes a run reproducible from archived artifacts.
    """

    run_id: str = Field(
        ...,
        description="Stable run identifier (ULID or UUID).",
    )
    spec: ScanSpecification = Field(
        ...,
        description="Frozen scan specification for this run.",
    )
    status: RunStatus = Field(
        default=RunStatus.QUEUED,
        description="Overall run status.",
    )
    started_at: datetime = Field(
        ...,
        description="UTC timestamp when the run started.",
    )
    finished_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when the run finished; None while running.",
    )
    source_commit_sha: str = Field(
        ...,
        description="Pinned commit SHA of the analyzed source.",
    )
    source_snapshot_hash: str = Field(
        ...,
        description="SHA-256 of the source tree snapshot as scanned.",
    )
    input_hashes: dict[str, str] = Field(
        default_factory=dict,
        description="Map of input artifact path -> SHA-256 digest.",
    )
    tool_versions: list[ToolVersionRecord] = Field(
        default_factory=list,
        description="Versions of every tool and container used.",
    )
    model_settings: list[ModelSettings] = Field(
        default_factory=list,
        description="Model settings snapshots for all providers used.",
    )
    stage_timings: list[StageTiming] = Field(
        default_factory=list,
        description="Timing and outcome of every stage attempt.",
    )
    usage: list[ProviderUsage] = Field(
        default_factory=list,
        description="Append-only provider usage records (tokens, cost, latency).",
    )
    failures: list[str] = Field(
        default_factory=list,
        description="Run-level failure descriptions (scanner crashes, unavailable AI, ...).",
    )
    artifact_checksums: dict[str, str] = Field(
        default_factory=dict,
        description="Map of artifact path -> SHA-256 digest for all outputs.",
    )
    artifacts: list[ArtifactReference] = Field(
        default_factory=list,
        description="Structured references to all run artifacts.",
    )
    worker_hostname: str | None = Field(
        default=None,
        description="Hostname of the worker that executed this run.",
    )
    worker_version: str | None = Field(
        default=None,
        description="Version of the vulnscan worker that executed this run.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form run metadata.",
    )

    def total_cost_usd(self) -> float:
        return round(sum(u.cost_usd for u in self.usage), 6)

    def total_tokens(self) -> int:
        return sum(u.total_tokens for u in self.usage)


__all__ = ["ModelSettings", "RunManifest", "StageTiming", "ToolVersionRecord"]
