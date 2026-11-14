"""Các scanner adapter cho pipeline của DevSecOps-Agent.

Mỗi adapter hiện thực :class:`vulnscan.scanners.base.ScannerAdapter` và
trả về một vỏ bọc (envelope) :class:`vulnscan.contracts.ScannerResult`. Adapter là nơi
*duy nhất* hiểu định dạng đầu ra đặc thù của từng nhà cung cấp: các giai đoạn phía sau
chỉ nhìn thấy các observation đã được chuẩn hóa.

Thiếu file thực thi (binary) là trường hợp được ghi nhận trong tài liệu, không bao giờ là ngoại lệ: adapter
ghi lại việc không khả dụng vào ``errors`` và trả về một kết quả có trạng thái là
``failed`` (hoặc ``skipped`` khi công cụ bị vô hiệu hóa trong scan spec).
"""

from __future__ import annotations

from .base import AdapterCapability, AdapterRegistry, ScannerAdapter
from .codeql_adapter import CodeQLAdapter
from .dependency_check_adapter import DependencyCheckAdapter
from .gitleaks_adapter import GitleaksAdapter
from .semgrep_adapter import SemgrepAdapter
from .spotbugs_adapter import SpotBugsAdapter

__all__ = [
    "AdapterCapability",
    "AdapterRegistry",
    "CodeQLAdapter",
    "DependencyCheckAdapter",
    "GitleaksAdapter",
    "ScannerAdapter",
    "SemgrepAdapter",
    "SpotBugsAdapter",
]
