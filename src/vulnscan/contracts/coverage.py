"""CoverageRecord — độ bao phủ phân tích theo từng đơn vị cho một công cụ (ACC-01, ACC-04, ACC-07).

Ghi lại các file nào đủ điều kiện và đã được phân tích, cùng các file bị phân tích một
phần, thất bại, không hỗ trợ, hoặc bị bỏ qua. Các đơn vị bị bỏ qua không bao giờ có thể
hiển thị là đã phân tích thành công. Độ bao phủ Java và JSP được đối chiếu riêng biệt
với danh mục đầu vào.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import (
    CoverageUnitStatus,
    CWECategory,
    ExtractionMode,
    LanguageKind,
    MissReason,
    ToolName,
)


class CoverageRecord(VersionedModel):
    """Độ bao phủ của một đơn vị phân tích bởi một công cụ."""

    run_id: str = Field(
        ...,
        description="RunManifest.run_id this coverage record belongs to.",
    )
    tool: ToolName = Field(
        ...,
        description="Scanner this coverage record describes.",
    )
    tool_version: str = Field(
        ...,
        description="Version of the scanner that produced this record.",
    )
    source_snapshot: str = Field(
        ...,
        description="Source revision or snapshot identifier analyzed (e.g. commit SHA).",
    )
    unit_path: str = Field(
        ...,
        description="File or analysis unit path, e.g. 'src/main/java/com/foo/Bar.java'.",
    )
    unit_language: LanguageKind = Field(
        default=LanguageKind.JAVA,
        description="Language of the analysis unit (Java and JSP reconcile separately).",
    )
    eligible: bool = Field(
        ...,
        description="True if the unit was in the scan specification's file scope.",
    )
    status: CoverageUnitStatus = Field(
        ...,
        description="Analysis outcome: analyzed, partial, failed, unsupported, skipped, not_eligible, not_processed.",
    )
    limitation_reason: str | None = Field(
        default=None,
        description="Why analysis was incomplete (parse failure, unsupported construct, timeout, ...).",
    )
    extraction_mode: ExtractionMode | None = Field(
        default=None,
        description="How the tool extracted the unit's structure (ACC-01).",
    )
    diagnostics: list[str] = Field(
        default_factory=list,
        description="Parsing/compilation diagnostics and unresolved calls preserved verbatim.",
    )
    unresolved_calls: list[str] = Field(
        default_factory=list,
        description="Calls the tool could not resolve (e.g. ambiguous method target).",
    )
    cwe_capabilities: list[CWECategory] = Field(
        default_factory=list,
        description="CWE groups this tool evaluated for this unit.",
    )
    cwe_limitations: list[CWECategory] = Field(
        default_factory=list,
        description="CWE groups this tool could not evaluate for this unit.",
    )
    duration_ms: int | None = Field(
        default=None,
        description="Wall-clock milliseconds spent analyzing this unit.",
        ge=0,
    )
    analyzed_at: datetime = Field(
        ...,
        description="UTC timestamp when coverage was recorded.",
    )
    miss_reasons: list[MissReason] = Field(
        default_factory=list,
        description="If the unit held a missed finding, why it was missed (ACC-07). Multiple reasons allowed.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form coverage metadata.",
    )


__all__ = ["CoverageRecord"]
