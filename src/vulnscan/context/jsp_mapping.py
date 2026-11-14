"""Ánh xạ các tệp JSP và tọa độ servlet được sinh ra từ chúng.

Biên dịch trước Jasper (JSP -> .java) là cách duy nhất để có được số dòng
chính xác cho các biểu thức JSP. Khi không khả dụng, chúng tôi ghi nhận một khoảng trống
độ phủ (ACC-04) và giữ tọa độ JSP ban đầu thay vì tự tạo ra tọa độ servlet được sinh.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class JspMapping:
    """Một tệp JSP và các điểm vào đã biết của nó."""

    jsp_path: str
    jsp_line_count: int = 0
    generated_java_path: str | None = None
    jasper_available: bool = False
    expressions: list[int] = field(default_factory=list)
    scriptlets: list[int] = field(default_factory=list)


_EXPR = re.compile(r"<%=")
_SCRIPTLET = re.compile(r"<%(?!=)")
_JASPER_MARKER = "_jsp.java"


def _jasper_output_for(jsp: Path, jasper_out: Path | None) -> Path | None:
    """Tìm tệp .java do Jasper sinh ra cho một JSP, nếu cây thư mục đầu ra tồn tại."""
    if jasper_out is None or not jasper_out.exists():
        return None
    rel = jsp.stem
    for cand in jasper_out.rglob(f"{rel}{_JASPER_MARKER}"):
        return cand
    # Bố cục Jasper cũ hơn: org/apache/jsp/<name>_jsp.java
    for cand in jasper_out.rglob(f"*{rel}*_jsp.java"):
        return cand
    return None


def index_jsp_files(
    snapshot: Path,
    jasper_output: Path | None = None,
) -> tuple[list[JspMapping], list[str]]:
    """Lập chỉ mục các JSP; trả về (mappings, coverage_gaps).

    ``jasper_output`` là cây thư mục đầu ra đã biên dịch trước. Khi nó vắng mặt,
    mọi JSP được ghi lại với ghi chú khoảng trống độ phủ (ACC-04): tọa độ servlet
    được sinh không bao giờ được tự ý bịa đặt.
    """
    snapshot = Path(snapshot)
    mappings: list[JspMapping] = []
    gaps: list[str] = []

    if not snapshot.exists():
        return mappings, gaps

    jasper_ok = jasper_output is not None and Path(jasper_output).exists()
    if not jasper_ok:
        gaps.append(
            "Jasper precompilation output unavailable; JSP findings keep "
            "original JSP coordinates (coverage gap ACC-04)"
        )

    for jsp in sorted(snapshot.rglob("*.jsp")):
        try:
            text = jsp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        m = JspMapping(
            jsp_path=str(jsp.relative_to(snapshot)) if jsp.is_relative_to(snapshot) else str(jsp),
            jsp_line_count=len(lines),
            expressions=[i + 1 for i, ln in enumerate(lines) if _EXPR.search(ln)],
            scriptlets=[i + 1 for i, ln in enumerate(lines) if _SCRIPTLET.search(ln)],
        )
        gen = _jasper_output_for(jsp, Path(jasper_output) if jasper_output else None)
        if gen is not None:
            m.generated_java_path = str(gen)
            m.jasper_available = True
        else:
            m.jasper_available = False
        mappings.append(m)

    return mappings, gaps
