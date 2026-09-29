"""ScanSpecification — the immutable input contract for a scan run.

Every downstream module (intake, scanners, normalization, assessment,
validation, reporting) reads its configuration from this single record.
Changes to a scan spec after creation require a new run.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, field_validator

from ._base import VersionedModel
from .enums import ToolName


class ToolConfig(VersionedModel):
    """Per-tool configuration embedded inside a scan specification."""

    tool: ToolName = Field(
        ...,
        description="Deterministic scanner to configure.",
    )
    enabled: bool = Field(
        default=True,
        description="Set False to skip this tool in the run.",
    )
    rule_paths: list[str] = Field(
        default_factory=list,
        description="Custom rule file paths; empty = use tool defaults.",
    )
    options: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific key/value options (validated by the adapter).",
    )


class ScanSpecification(VersionedModel):
    """Describes everything needed to reproduce a scan run.

    Once a run is queued the spec is frozen; the runner persists a snapshot
    with the :class:`RunManifest` so the exact input is recoverable.
    """

    run_id: str | None = Field(
        default=None,
        description="RunManifest.run_id this spec belongs to; None until a run is created.",
    )
    target_repository_url: str = Field(
        ...,
        description="Git clone URL of the target repository.",
    )
    target_commit_sha: str = Field(
        ...,
        description="Pinned commit SHA (full or short, never 'HEAD').",
    )

    @field_validator("target_commit_sha")
    @classmethod
    def _reject_moving_target(cls, v: str) -> str:
        """A scan must be reproducible, so a moving ref is not a valid pin."""
        if v.strip().upper() in {"HEAD", "MAIN", "MASTER", "TRUNK"}:
            raise ValueError(
                f"target_commit_sha must be a pinned commit SHA, not a moving branch ref ({v!r})"
            )
        return v

    repository_checkout_path: str = Field(
        default=".",
        description="Relative or absolute path to an already-checked-out working copy.",
    )
    language: str = Field(
        default="java",
        description="Primary source language of the target (e.g. 'java', 'jsp').",
    )
    file_scope_include: list[str] = Field(
        default_factory=lambda: ["**/*.java", "**/*.jsp"],
        description="Glob patterns for files eligible for scanning.",
    )
    file_scope_exclude: list[str] = Field(
        default_factory=lambda: [
            "**/target/**",
            "**/build/**",
            "**/.git/**",
            "**/node_modules/**",
        ],
        description="Glob patterns for files excluded from scanning.",
    )
    tools: list[ToolConfig] = Field(
        default_factory=lambda: [
            ToolConfig(tool=ToolName.SEMGREP),
            ToolConfig(tool=ToolName.SPOTBUGS, enabled=False),
            ToolConfig(tool=ToolName.OWASP_DEPENDENCY_CHECK, enabled=False),
            ToolConfig(tool=ToolName.GITLEAKS, enabled=False),
            ToolConfig(tool=ToolName.CODEQL, enabled=False),
        ],
        description="Tool configurations for this run.",
    )
    rules_packs_version: str = Field(
        default="0.1.0",
        description="Version of the custom detection rule packs (ACC-05).",
    )
    context_profile: str = Field(
        default="default",
        description="Named context profile selecting models, policies, and assumptions.",
    )
    authorization_policy_version: str | None = Field(
        default=None,
        description="Version of the authorization policy (ACC-03) to use.",
    )
    max_file_count: int | None = Field(
        default=None,
        description="Hard cap on files processed per tool; None = unlimited.",
        ge=1,
    )
    max_tokens_budget: int | None = Field(
        default=None,
        description="Token budget across all provider calls; None = unlimited.",
        ge=1,
    )
    max_cost_usd: float | None = Field(
        default=None,
        description="USD budget cap across all provider calls; None = unlimited.",
        ge=0.0,
    )
    max_wall_seconds: int | None = Field(
        default=None,
        description="Wall-clock budget for the whole run; None = unlimited.",
        ge=1,
    )
    verification_level: str = Field(
        default="static",
        description=(
            "Verification depth: 'static' (default), 'junit' (isolated tests), "
            "or 'sandbox' (targeted container execution)."
        ),
    )
    sandbox_image: str | None = Field(
        default=None,
        description="Docker image used for sandbox execution.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the specification was authored.",
    )
    created_by: str = Field(
        default="cli",
        description="Originator of the scan (e.g. 'cli', 'api', 'scheduler').",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form metadata for traceability.",
    )


__all__ = ["ScanSpecification", "ToolConfig"]
