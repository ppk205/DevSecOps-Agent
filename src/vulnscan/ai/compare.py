"""So sánh các lỗ hổng do mô hình săn tìm với các finding từ scanner xác định (deterministic).

Hàm thuần túy, không I/O. Khóa khớp: (đường dẫn posix chuẩn hóa, dung sai dòng ±3 dòng,
các chữ số CWE với bản đồ fallback rule->CWE được tạo lúc runtime từ
``src/vulnscan/scanners/rules/*.yml`` ``metadata.cwe``).

Trả về ``{"agreed": [...], "model_only": [...], "scanner_only": [...],
"counts": {...}}``. Chỉ dùng cho báo cáo: các mục khớp được tham chiếu chéo, các finding
đã lưu không bao giờ bị hợp nhất hay chỉnh sửa.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_LINE_TOLERANCE = 3

# Thư mục chứa các bộ quy tắc semgrep (java/javascript/python/php yml).
_RULES_DIR = Path(__file__).resolve().parent.parent / "scanners" / "rules"

# Được phân tích một lần ở lượt sử dụng đầu tiên, sau đó lưu cache trong module state.
_rule_cwe_cache: dict[str, str] | None = None

_CWE_DIGITS = re.compile(r"(\d+)")
_RULE_ID_LINE = re.compile(r"^\s*-\s*id\s*:\s*(\S+)\s*$")


def _scan_rules_text(text: str) -> dict[str, str]:
    """Trích xuất ``{rule id: CWE digits}`` từ nội dung văn bản của một tệp rules.

    Mỗi khối rule khai báo ``- id: <rule-id>`` theo sau bởi phần ``metadata:``
    với một mục ``cwe: ['CWE-NNN: ...']`` trên một dòng đơn. Quá trình quét
    theo dõi rule id gần nhất và ghi lại mục CWE đầu tiên tìm thấy bên dưới nó
    — không yêu cầu phụ thuộc thư viện YAML.
    """
    mapping: dict[str, str] = {}
    current_id = ""
    for line in text.splitlines():
        id_match = _RULE_ID_LINE.match(line)
        if id_match:
            current_id = id_match.group(1)
            continue
        if current_id and current_id not in mapping and "cwe" in line and "CWE" in line.upper():
            cwe_match = _CWE_DIGITS.search(line)
            if cwe_match:
                mapping[current_id] = cwe_match.group(1)
    return mapping


def _load_rule_cwe_map() -> dict[str, str]:
    """Xây dựng ánh xạ rule id -> CWE digits từ mỗi tệp ``rules/*.yml``."""
    mapping: dict[str, str] = {}
    try:
        files = sorted(_RULES_DIR.glob("*.yml"))
    except OSError:
        return mapping
    for rules_file in files:
        try:
            text = rules_file.read_text(encoding="utf-8")
        except OSError:
            continue
        mapping.update(_scan_rules_text(text))
    return mapping


def rule_cwe_map() -> dict[str, str]:
    """Bản đồ rule->CWE lúc runtime (phân tích một lần, lưu cache); ``{}`` khi không khả dụng."""
    global _rule_cwe_cache
    if _rule_cwe_cache is None:
        _rule_cwe_cache = _load_rule_cwe_map()
    return _rule_cwe_cache


def _rule_cwe(rule_id: str) -> str:
    """Các chữ số CWE cho một rule id thuộc bất kỳ tiền tố ngôn ngữ nào; ``""`` khi không xác định."""
    return rule_cwe_map().get(rule_id, "")


def norm_path(path: str) -> str:
    """Chuẩn hóa thành đường dẫn posix có thể so sánh được (loại bỏ tiền tố ``./``)."""
    text = str(path or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def cwe_digits(value: Any) -> str:
    """Trích xuất các chữ số CWE (``CWE-89`` -> ``89``); ``""`` khi không có."""
    if value is None:
        return ""
    match = _CWE_DIGITS.search(str(value))
    return match.group(1) if match else ""


def _candidate_cwe(candidate: Any) -> str:
    if isinstance(candidate, dict):
        return cwe_digits(candidate.get("cwe"))
    return cwe_digits(getattr(candidate, "cwe", None))


def _candidate_location(candidate: Any) -> tuple[str, int]:
    if isinstance(candidate, dict):
        try:
            line = int(candidate.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        return norm_path(str(candidate.get("file", ""))), line
    line = getattr(candidate, "line", 0)
    try:
        line = int(line or 0)
    except (TypeError, ValueError):
        line = 0
    return norm_path(str(getattr(candidate, "file", ""))), line


def _finding_cwe(finding: Any) -> str:
    if isinstance(finding, dict):
        direct = cwe_digits(finding.get("cwe") or finding.get("cwe_category"))
        if direct:
            return direct
        return _rule_cwe(str(finding.get("rule_id", "")))
    cwe = cwe_digits(getattr(finding, "cwe_category", None))
    if cwe:
        return cwe
    for obs in getattr(finding, "observations", []) or []:
        cwe = cwe_digits(getattr(obs, "cwe_category", None))
        if cwe:
            return cwe
        rule_cwe = _rule_cwe(str(getattr(obs, "rule_id", "")))
        if rule_cwe:
            return rule_cwe
    return ""


def _finding_location(finding: Any) -> tuple[str, int]:
    if isinstance(finding, dict):
        try:
            line = int(finding.get("line", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        return norm_path(str(finding.get("file", ""))), line
    for obs in getattr(finding, "observations", []) or []:
        location = getattr(obs, "location", None)
        if location is None:
            continue
        try:
            line = int(getattr(location, "line_start", 0) or 0)
        except (TypeError, ValueError):
            line = 0
        return norm_path(str(getattr(location, "file_path", ""))), line
    return "", 0


def compare_hunt_vs_scanners(candidates: list[Any], findings: list[Any]) -> dict[str, Any]:
    """Phân nhóm ứng viên được săn tìm với các finding của scanner theo (path, line±3, CWE).

    Một ứng viên khớp với một finding khi đường dẫn trùng khớp hoàn toàn sau khi chuẩn hóa,
    dòng nằm trong khoảng ±3 và các chữ số CWE trùng khớp — hoặc một trong hai bên
    không mang thông tin CWE (khi đó chỉ path+line sẽ quyết định). Mỗi finding
    khớp tối đa với một ứng viên (ưu tiên ứng viên đầu tiên, giữ nguyên thứ tự đầu vào).
    """
    agreed: list[dict[str, Any]] = []
    matched_findings: set[int] = set()
    matched_candidates: set[int] = set()

    finding_keys = [(_finding_location(f), _finding_cwe(f)) for f in findings]
    for ci, candidate in enumerate(candidates or []):
        (c_path, c_line), c_cwe = _candidate_location(candidate), _candidate_cwe(candidate)
        for fi, finding in enumerate(findings or []):
            if fi in matched_findings:
                continue
            (f_path, f_line), f_cwe = finding_keys[fi]
            if not c_path or c_path != f_path:
                continue
            if abs(c_line - f_line) > _LINE_TOLERANCE:
                continue
            if c_cwe and f_cwe and c_cwe != f_cwe:
                continue
            agreed.append({"candidate": candidate, "finding": finding})
            matched_findings.add(fi)
            matched_candidates.add(ci)
            break

    model_only = [c for i, c in enumerate(candidates or []) if i not in matched_candidates]
    scanner_only = [f for i, f in enumerate(findings or []) if i not in matched_findings]
    return {
        "agreed": agreed,
        "model_only": model_only,
        "scanner_only": scanner_only,
        "counts": {
            "agreed": len(agreed),
            "model_only": len(model_only),
            "scanner_only": len(scanner_only),
        },
    }
