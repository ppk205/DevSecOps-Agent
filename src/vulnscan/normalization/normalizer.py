"""Bộ chuẩn hóa: ScannerResult -> list[Observation].

Xác thực từng observation theo các ràng buộc contract (CWE không hợp lệ, thiếu vị trí).
Không bao giờ tự tạo tọa độ. Hàm thuần túy (pure): hoạt động trên dữ liệu đã được nạp sẵn.
"""

from __future__ import annotations

from vulnscan.contracts import CWECategory, Observation, ScannerResult


def normalize_result(result: ScannerResult) -> list[Observation]:
    """Trích xuất và xác thực các observation từ một scanner result.

    Các observation không hợp lệ (sai CWE, thiếu tọa độ) sẽ bị loại bỏ — chúng
    không bao giờ đi tới giai đoạn nhóm.
    """
    valid: list[Observation] = []
    for obs in result.observations:
        if not _is_valid_cwe(obs):
            continue
        if not _has_location(obs):
            continue
        valid.append(obs)
    return valid


def _is_valid_cwe(obs: Observation) -> bool:
    """CWE phải là một thành viên của enum CWECategory (hoặc không có)."""
    if obs.cwe_category is None:
        return True  # các finding về dependency có thể thiếu một CWE rõ ràng
    return isinstance(obs.cwe_category, CWECategory)


def _has_location(obs: Observation) -> bool:
    """Mỗi observation phải mang một tọa độ source kèm theo đường dẫn file."""
    return obs.location is not None and bool(obs.location.file_path)
