"""Chuẩn hóa finding: ScannerResult -> Observations đã xác thực -> Findings đã nhóm."""

from .dedup import deduplicate_findings
from .grouping import group_findings
from .normalizer import normalize_result

__all__ = ["deduplicate_findings", "group_findings", "normalize_result"]
