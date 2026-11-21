"""Engine tìm kiếm vết bẩn (taint-hunt) regex thuần: luồng vết bẩn không dùng Semgrep hoặc model.

Các rule pack nằm trong ``rules/<family>.json`` theo hai cấu trúc: dạng cổng chuyển
(``{"language": ..., "rules": [...]}`` với sink ``patterns`` được chuyển từ
``src/vulnscan/scanners/rules/*.yml``, sử dụng sources/sanitizers mặc định
của họ đó) và dạng taint (danh sách JSON chứa
``sources``/``sinks``/``sanitizers``). Xem
:mod:`vulnscan.native_hunt.taint`.
"""

from __future__ import annotations

from .engine import (
    FAMILY_EXTENSIONS,
    MAX_FILE_BYTES,
    MAX_ITERATIONS,
    Finding,
    SnapshotResult,
    scan_file,
    scan_snapshot,
)
from .taint import RULES_DIR, Rule, Sanitizer, load_rules

__all__ = [
    "FAMILY_EXTENSIONS",
    "MAX_FILE_BYTES",
    "MAX_ITERATIONS",
    "RULES_DIR",
    "Finding",
    "Rule",
    "Sanitizer",
    "SnapshotResult",
    "load_rules",
    "scan_file",
    "scan_snapshot",
]
