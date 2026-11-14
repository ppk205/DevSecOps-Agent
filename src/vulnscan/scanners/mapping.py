"""Giải thích mã thoát và ánh xạ CWE dùng chung cho các scanner adapter."""

from __future__ import annotations

import re
from typing import Any

from vulnscan.contracts import CWECategory, Severity

# Các mã thoát (exit code) phổ biến của CLI scanner. Các adapter không bao giờ được coi một mã
# chưa được ghi nhận trong tài liệu là thành công; mã không xác định sẽ được báo là lỗi kèm stderr thô.
_SEMGREP_EXIT_CODES = {
    0: "no findings",
    1: "findings present (semgrep convention)",
    2: "semgrep ran with errors",
    7: "invalid rule schema",
    8: "missing required argument",
}

# --- native severity -> reference severity ----------------------------------

_NATIVE_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "blocker": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
}

# Mức ưu tiên của SpotBugs -> reference severity (theo tài liệu SpotBugs).
_SPOTBUGS_PRIORITY: dict[str, Severity] = {
    "1": Severity.HIGH,
    "2": Severity.MEDIUM,
    "3": Severity.LOW,
}


def map_severity(native: str | None) -> Severity:
    """Ánh xạ chuỗi severity gốc sang thang đo tham chiếu.

    Các giá trị không xác định sẽ trở thành :attr:`Severity.UNDETERMINED` thay vì suy đoán.
    """
    if not native:
        return Severity.UNDETERMINED
    return _NATIVE_SEVERITY.get(native.strip().lower(), Severity.UNDETERMINED)


def map_spotbugs_priority(priority: str | int | None) -> Severity:
    """Ánh xạ mức ưu tiên của SpotBugs (1/2/3) sang thang đo severity tham chiếu."""
    key = str(priority).strip() if priority is not None else ""
    return _SPOTBUGS_PRIORITY.get(key, Severity.UNDETERMINED)


# --- phân tích nhãn CWE --------------------------------------------------

_CWE_RE = re.compile(r"CWE[-\s]?(\d{1,6})", re.IGNORECASE)


def parse_cwe_labels(value: Any) -> list[str]:
    """Trích xuất các nhãn ``CWE-<n>`` đã chuẩn hóa từ giá trị do công cụ cung cấp.

    Chấp nhận chuỗi ("CWE-89, CWE-79"), danh sách chuỗi, hoặc danh sách dict
    có các khóa ``id``/``cweId``/``name`` (theo kiểu NVD JSON). Trả về danh sách
    đã khử trùng lặp theo thứ tự xuất hiện đầu tiên; danh sách rỗng nghĩa là công cụ không chỉ định CWE nào.
    """
    if value is None:
        return []
    candidates: list[str] = []
    if isinstance(value, str):
        candidates.append(value)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, str):
                candidates.append(item)
            elif isinstance(item, dict):
                for k in ("id", "cweId", "cwe", "name", "label"):
                    if k in item and isinstance(item[k], str):
                        candidates.append(str(item[k]))
    elif isinstance(value, dict):
        for k in ("id", "cweId", "cwe", "name", "label"):
            if k in value and isinstance(value[k], str):
                candidates.append(str(value[k]))

    out: list[str] = []
    seen: set[str] = set()
    for cand in candidates:
        for m in _CWE_RE.finditer(cand):
            label = f"CWE-{int(m.group(1))}"
            if label not in seen:
                seen.add(label)
                out.append(label)
    return out


def cwe_category(label: str | None) -> CWECategory | None:
    """Trả về :class:`CWECategory` phù hợp, nếu không thì trả về ``None``.

    ``None`` (không phải ``UNCLASSIFIED``) có nghĩa là không thể ánh xạ nhãn của công cụ;
    bộ chuẩn hóa sẽ quyết định loại bỏ hoặc hạ cấp observation.
    """
    if not label:
        return None
    norm = label.strip().upper()
    norm = re.sub(r"\s+", "-", norm)
    if not norm.startswith("CWE-"):
        norm = f"CWE-{norm}" if norm.isdigit() else norm
    for member in CWECategory:
        if member.value == norm:
            return member
    return None


def first_mapped_cwe(labels: list[str]) -> CWECategory | None:
    """Nhãn đầu tiên ánh xạ vào một :class:`CWECategory` đã biết, nếu không thì trả về None."""
    for label in labels:
        cat = cwe_category(label)
        if cat is not None:
            return cat
    return None


def confidence_value(value: Any, default: float = 1.0) -> float:
    """Giới hạn độ tin cậy do công cụ báo cáo trong khoảng [0.0, 1.0]."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, v))


def semgrep_exit_meaning(code: int) -> str:
    """Ý nghĩa dễ hiểu cho con người của một mã thoát semgrep."""
    return _SEMGREP_EXIT_CODES.get(code, f"unknown exit code {code}")


__all__ = [
    "confidence_value",
    "cwe_category",
    "first_mapped_cwe",
    "map_severity",
    "map_spotbugs_priority",
    "parse_cwe_labels",
    "semgrep_exit_meaning",
]
