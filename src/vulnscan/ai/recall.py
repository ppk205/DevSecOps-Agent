"""Recall của hunt so với đường cơ sở native xác định (file + line ±3).

Hàm thuần túy, không I/O: harness trực tiếp (``scripts/hunt_recall.py``) nạp
các native finding từ :mod:`vulnscan.native_hunt` và các ứng viên hunt từ
``hunt_all`` / ``hunt.json``; unit test nạp các fixture nội dòng.

Khóa khớp phản ánh đúng đặc tả tác vụ: đường dẫn posix chuẩn hóa phải bằng nhau và
khoảng cách dòng tuyệt đối ≤ 3. CWE được cố tình bỏ qua — câu hỏi là
liệu mô hình có nhìn đúng vị trí hay không, chứ không phải liệu nó có đặt tên
điểm yếu chính xác hay không (đó là điều ``compare_hunt_vs_scanners`` kiểm tra).
"""

from __future__ import annotations

from typing import Any


def norm_path(path: Any) -> str:
    """Chuẩn hóa thành đường dẫn posix có thể so sánh được (loại bỏ tiền tố ``./``)."""
    text = str(path or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _line_of(item: Any, keys: tuple[str, ...] = ("line",)) -> int:
    if isinstance(item, dict):
        for key in keys:
            try:
                return int(item.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
        return 0
    for key in keys:
        try:
            return int(getattr(item, key, 0) or 0)
        except (TypeError, ValueError):
            continue
    return 0


def _file_of(item: Any, keys: tuple[str, ...] = ("file",)) -> str:
    if isinstance(item, dict):
        for key in keys:
            value = item.get(key)
            if value:
                return norm_path(value)
        return ""
    for key in keys:
        value = getattr(item, key, None)
        if value:
            return norm_path(value)
    return ""


def match_candidates_to_native(
    candidates: list[Any],
    native: list[Any],
    *,
    tolerance: int = 3,
) -> dict[str, Any]:
    """Khớp các ứng viên hunt với các native finding theo (path, line±tol).

    Mỗi native finding khớp tối đa với một ứng viên (ưu tiên mục đầu tiên, giữ nguyên
    thứ tự đầu vào). Trả về danh sách matched/missed cùng với recall theo từng native rule
    khi các mục native chứa ``rule_id``.
    """
    tol = max(0, int(tolerance))
    native_keys = [(_file_of(n), _line_of(n)) for n in (native or [])]
    matched_native: set[int] = set()
    matched_candidates: set[int] = set()
    pairs: list[dict[str, Any]] = []
    for ci, candidate in enumerate(candidates or []):
        c_path, c_line = _file_of(candidate), _line_of(candidate)
        if not c_path or c_line < 1:
            continue
        for ni, (n_path, n_line) in enumerate(native_keys):
            if ni in matched_native or not n_path or n_line < 1:
                continue
            if c_path != n_path or abs(c_line - n_line) > tol:
                continue
            matched_native.add(ni)
            matched_candidates.add(ci)
            pairs.append({"candidate": candidate, "native": native[ni]})
            break
    total_native = len(list(native or []))
    total_candidates = len(list(candidates or []))
    matched = len(matched_native)
    recall = (matched / total_native) if total_native else 0.0
    precision = (len(matched_candidates) / total_candidates) if total_candidates else 0.0
    by_rule: dict[str, dict[str, int]] = {}
    for ni, item in enumerate(native or []):
        rule = str(item.get("rule_id", "unknown") if isinstance(item, dict) else "unknown")
        bucket = by_rule.setdefault(rule, {"total": 0, "matched": 0})
        bucket["total"] += 1
        if ni in matched_native:
            bucket["matched"] += 1
    return {
        "matched": matched,
        "total_native": total_native,
        "total_candidates": total_candidates,
        "recall": recall,
        "precision": precision,
        "pairs": pairs,
        "missed_native": [n for i, n in enumerate(native or []) if i not in matched_native],
        "unmatched_candidates": [
            c for i, c in enumerate(candidates or []) if i not in matched_candidates
        ],
        "by_rule": by_rule,
    }


def recall_report(match: dict[str, Any]) -> str:
    """Tóm tắt ngắn một đoạn cho con người về kết quả :func:`match`."""
    return (
        f"recall {match['matched']}/{match['total_native']} "
        f"({match['recall'] * 100:.1f}%) vs native; "
        f"hunt candidates {match['total_candidates']} "
        f"(precision {match['precision'] * 100:.1f}%)"
    )
