"""Lập chỉ mục mã nguồn Java cho các điểm vào liên quan đến bảo mật.

Phân tích cú pháp thuần Python các annotation @WebServlet/@WebFilter và bộ mô tả triển khai
web.xml cổ điển. Đồng thời lập chỉ mục các trình trợ giúp auth (các tệp gọi
authenticate/authorize). Không dùng reflection, không dùng mạng.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET


@dataclass
class ServletEntry:
    name: str
    url_pattern: str
    class_name: str
    declared_in_annotation: bool = True


@dataclass
class FilterEntry:
    name: str
    url_pattern: str
    class_name: str
    declared_in_annotation: bool = True


@dataclass
class SourceIndex:
    """Các điểm vào và hàm trợ giúp auth đã được lập chỉ mục cho snapshot."""

    servlets: list[ServletEntry] = field(default_factory=list)
    filters: list[FilterEntry] = field(default_factory=list)
    web_xml_paths: list[str] = field(default_factory=list)
    annotation_scan_gaps: list[str] = field(default_factory=list)
    auth_helper_files: list[str] = field(default_factory=list)


_ANNOT_BLOCK = re.compile(r"@(?:WebServlet|WebFilter)\s*\(([^\)]*)\)", re.DOTALL)
_QUOTED = re.compile(r"['\"]([^'\"]+)['\"]")
_CLASS_NAME = re.compile(r"class\s+(\w+)")
_AUTH_CALL = re.compile(r"\b(authenticate|authorize|login|logout|isAuthenticated|hasRole)\s*\(")


def _annotation_url_patterns(source: str) -> list[str]:
    """Trích xuất url-patterns từ phần thân annotation @WebServlet/@WebFilter."""
    patterns: list[str] = []
    for m in _ANNOT_BLOCK.finditer(source):
        for q in _QUOTED.finditer(m.group(1)):
            if q.group(1).startswith("/"):
                patterns.append(q.group(1))
    return patterns


def _class_name_of(source: str) -> str | None:
    m = _CLASS_NAME.search(source)
    return m.group(1) if m else None


def index_web_xml(web_xml: Path) -> tuple[list[ServletEntry], list[FilterEntry]]:
    """Phân tích cú pháp các ánh xạ servlet + filter trong web.xml (kiểu cổ điển)."""
    servlets: list[ServletEntry] = []
    filters: list[FilterEntry] = []
    try:
        tree = ET.parse(web_xml)
    except ET.ParseError:
        return servlets, filters
    root = tree.getroot()

    # servlet-name -> class
    servlet_classes: dict[str, str] = {}
    for s in root.iter("servlet"):
        name = s.findtext("servlet-name")
        cls = s.findtext("servlet-class")
        if name and cls:
            servlet_classes[name] = cls
    for sm in root.iter("servlet-mapping"):
        name = sm.findtext("servlet-name")
        pattern = sm.findtext("url-pattern")
        if name and pattern:
            servlets.append(
                ServletEntry(
                    name=name,
                    url_pattern=pattern,
                    class_name=servlet_classes.get(name, name),
                    declared_in_annotation=False,
                )
            )

    # filter-name -> class
    filter_classes: dict[str, str] = {}
    for f in root.iter("filter"):
        name = f.findtext("filter-name")
        cls = f.findtext("filter-class")
        if name and cls:
            filter_classes[name] = cls
    for fm in root.iter("filter-mapping"):
        name = fm.findtext("filter-name")
        pattern = fm.findtext("url-pattern")
        if name and pattern:
            filters.append(
                FilterEntry(
                    name=name,
                    url_pattern=pattern,
                    class_name=filter_classes.get(name, name),
                    declared_in_annotation=False,
                )
            )
    return servlets, filters


def build_source_index(snapshot: Path) -> SourceIndex:
    """Quét thư mục gốc của snapshot để tìm các điểm vào + hàm trợ giúp auth."""
    snapshot = Path(snapshot)
    idx = SourceIndex()
    if not snapshot.exists():
        return idx

    # 1. web.xml (có thể vắng mặt hoặc bị phân chia qua các mảnh fragment)
    for web_xml in snapshot.rglob("web.xml"):
        s, f = index_web_xml(web_xml)
        idx.servlets.extend(s)
        idx.filters.extend(f)
        idx.web_xml_paths.append(str(web_xml))
        if not s and not f:
            idx.annotation_scan_gaps.append(
                f"{web_xml}: parsed but contained no servlet/filter mappings"
            )

    # 2. Các khai báo dựa trên annotation
    for java in snapshot.rglob("*.java"):
        try:
            source = java.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        cls = _class_name_of(source)
        if not cls:
            continue
        patterns = _annotation_url_patterns(source)
        if not patterns:
            continue
        if "@WebServlet" in source:
            for p in patterns:
                idx.servlets.append(
                    ServletEntry(
                        name=cls, url_pattern=p, class_name=cls, declared_in_annotation=True
                    )
                )
        if "@WebFilter" in source:
            for p in patterns:
                idx.filters.append(
                    FilterEntry(
                        name=cls, url_pattern=p, class_name=cls, declared_in_annotation=True
                    )
                )

    # 3. Các hàm trợ giúp auth
    for java in snapshot.rglob("*.java"):
        try:
            source = java.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _AUTH_CALL.search(source):
            idx.auth_helper_files.append(str(java))

    return idx
