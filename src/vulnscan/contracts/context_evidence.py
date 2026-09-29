"""ContextEvidence — per-finding source-map context assembled during analysis (ACC-01–04).

Captures route, filters, callers, sinks, dataflow paths, ambiguous resolutions,
and JSP output context.  Ambiguous call resolution remains explicit so the
reader knows when a path is uncertain.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import CWECategory, ExtractionMode, LanguageKind


class DataflowPath(VersionedModel):
    """One source-to-sink dataflow path, including its provenance."""

    path_id: str = Field(
        ...,
        description="Stable identifier for this path within the finding context.",
    )
    source_location: str = Field(
        ...,
        description="Source coordinate, e.g. 'src/main/java/com/foo/Servlet.java:42'.",
    )
    sink_location: str = Field(
        ...,
        description="Sink coordinate.",
    )
    intermediate_locations: list[str] = Field(
        default_factory=list,
        description="Intermediate node locations along the path.",
    )
    extraction_mode: ExtractionMode = Field(
        ...,
        description="How this path was derived (AST, dataflow, pattern, etc.).",
    )
    tool: str = Field(
        ...,
        description="Tool or query that discovered this path, e.g. 'semgrep', 'codeql:sql-injection'.",
    )
    query_version: str | None = Field(
        default=None,
        description="Version of the CodeQL query or Semgrep rule that found this path.",
    )
    confidence: float = Field(
        default=1.0,
        description="Tool-reported path confidence (0.0–1.0).",
        ge=0.0,
        le=1.0,
    )
    notes: str = Field(
        default="",
        description="Extra notes about the path, e.g. 'ambiguous call to helper'.",
    )


class AmbiguousResolution(VersionedModel):
    """Records an unresolved or uncertain call resolution.

    Preserved explicitly rather than silently dropped.
    """

    location: str = Field(
        ...,
        description="Source coordinate where ambiguity was encountered.",
    )
    description: str = Field(
        ...,
        description="What is ambiguous (e.g. 'polymorphic call to IValidator.validate').",
    )
    possible_targets: list[str] = Field(
        default_factory=list,
        description="Candidate target methods/classes if known.",
    )
    resolution_method: str | None = Field(
        default=None,
        description="How the ambiguity was handled (e.g. 'conservative_union', 'manual_review').",
    )


class JSPContext(VersionedModel):
    """JSP-specific output context (ACC-04).

    Tracks HTML text, attributes, URLs, and JavaScript contexts where
    expressions are embedded.
    """

    jsp_file: str = Field(
        ...,
        description="Path to the JSP file.",
    )
    output_line: int | None = Field(
        default=None,
        description="Line number in the JSP or compiled HTML output.",
        ge=1,
    )
    output_context: str = Field(
        ...,
        description=(
            "Where the expression is embedded: 'html_text', 'html_attribute', "
            "'url', 'javascript', 'css', 'template_directive'."
        ),
    )
    original_source_mapping: str | None = Field(
        default=None,
        description=(
            "Mapping from JSP expression to compiled servlet line (e.g. 'JSP:12 -> Servlet:45')."
        ),
    )
    is_escaped: bool = Field(
        default=False,
        description="Whether the output is auto-escaped by the template engine.",
    )
    notes: str = Field(
        default="",
        description="Notes about output context or escaping.",
    )


class ContextEvidence(VersionedModel):
    """Full context evidence record for one finding or observation.

    Each finding carries its own ContextEvidence; records are never shared
    across findings even when they overlap.
    """

    evidence_id: str = Field(
        ...,
        description="Stable identifier for this context-evidence record.",
    )
    finding_id: str = Field(
        ...,
        description="Finding this context evidence belongs to.",
    )
    cwe_category: CWECategory | None = Field(
        default=None,
        description="CWE group this context applies to.",
    )
    route: str | None = Field(
        default=None,
        description="HTTP route or endpoint where the vulnerability is reachable.",
    )
    filters: list[str] = Field(
        default_factory=list,
        description="Servlet filters or middleware that process requests before reaching the vulnerable code.",
    )
    callers: list[str] = Field(
        default_factory=list,
        description="Methods or classes that invoke the vulnerable code path.",
    )
    sinks: list[str] = Field(
        default_factory=list,
        description="Dangerous operations or APIs reached from the source.",
    )
    dataflow_paths: list[DataflowPath] = Field(
        default_factory=list,
        description="Source-to-sink dataflow paths.",
    )
    ambiguous_resolutions: list[AmbiguousResolution] = Field(
        default_factory=list,
        description="Unresolved call resolutions preserved for transparency.",
    )
    jsp_context: JSPContext | None = Field(
        default=None,
        description="JSP output context if applicable (ACC-04).",
    )
    source_language: LanguageKind = Field(
        default=LanguageKind.JAVA,
        description="Language of the source unit this context applies to.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form context metadata.",
    )


__all__ = [
    "AmbiguousResolution",
    "ContextEvidence",
    "DataflowPath",
    "JSPContext",
]
