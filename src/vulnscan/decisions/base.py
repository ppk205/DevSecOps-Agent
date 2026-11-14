"""Protocol cho các decision backend cục bộ tùy chọn."""

from __future__ import annotations

from typing import Protocol

from vulnscan.contracts.decision import DecisionRequest, DecisionResult


class DecisionBackend(Protocol):
    """Giao diện quyết định được định kiểu nhỏ gọn; cố ý không phải là một chat provider."""

    def predict(self, request: DecisionRequest) -> DecisionResult:
        """Trả về một quyết định tham vấn có cấu trúc mà không ném ngoại lệ khi mô hình gặp lỗi."""
