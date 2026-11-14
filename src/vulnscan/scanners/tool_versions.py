"""Các helper gọn nhẹ để kiểm tra phiên bản công cụ và xây dựng danh sách đối số."""

from __future__ import annotations

from typing import Any

from vulnscan.contracts import ScanSpecification

from .platform import which
from .process import run_command


def probe_version(binary: str) -> str | None:
    """Thử ``<binary> --version`` (hoặc ``-version``) và trả về dòng đầu tiên.

    Trả về ``None`` khi không có binary hoặc binary không phản hồi. Thời gian
    timeout được thiết lập dư dả vì lần gọi đầu tiên của một binary mới cài đặt
    có thể mất hàng chục giây trong khi OS kiểm tra file thực thi mới;
    các lệnh gọi sau (warm call) sẽ phản hồi trong vài giây.
    """
    resolved = which(binary)
    if resolved is None:
        return None
    for flag in ("--version", "-version"):
        result = run_command((binary, flag), timeout=30)
        if result.succeeded and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    return None


def java_target_classpath(spec: ScanSpecification) -> str | None:
    """Trả về đường dẫn thư mục ``classes/`` đã biên dịch nếu tồn tại.

    SpotBugs yêu cầu bytecode đã biên dịch; helper này tìm thấy nó dưới
    cấu trúc thư mục Maven tiêu chuẩn có gốc tại ``<repo>/target/classes``.
    """
    path = spec.metadata.get("build_artifacts", {}).get("classes_dir")
    return str(path) if path else None


def classpath_from_options(tool_cfg: Any) -> str | None:
    """Lấy ``classpath`` từ các tùy chọn theo từng công cụ, hoặc trả về ``None``."""
    if tool_cfg is None:
        return None
    return getattr(tool_cfg, "options", {}).get("classpath")


__all__ = ["classpath_from_options", "java_target_classpath", "probe_version"]
