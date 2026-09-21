"""Finding normalization: ScannerResult -> validated Observations -> grouped Findings."""

from .normalizer import normalize_result
from .grouping import group_findings
from .dedup import deduplicate_findings

__all__ = ["normalize_result", "group_findings", "deduplicate_findings"]
