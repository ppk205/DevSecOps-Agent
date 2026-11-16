"""Tải thông tin xác thực từ các biến môi trường.

Khóa API không bao giờ được trả về cho bên gọi dưới dạng có thể nhúng vào
báo cáo, log, hoặc bản ghi trao đổi của model. Hàm trợ giúp ``redact`` sẽ loại bỏ
các giá trị có định dạng thông tin xác thực trước khi bất kỳ kết quả nào ra khỏi ranh giới provider.
"""

from __future__ import annotations

import os
import re

# Các pattern theo định dạng cụ thể cho thông tin xác thực thực tế. Được thu hẹp có chủ ý:
# các từ đơn lẻ như "token", "key", hoặc "secret" không bao giờ kích hoạt che giấu (redaction), vì vậy
# các định danh code (``token.isEmpty()``), các dòng diff +/-, và payload JSON
# được giữ nguyên vẹn mà không bị can thiệp.
_FORMAT_RES = (
    re.compile(r"sk-[A-Za-z0-9_-]{8,}"),  # Khóa bí mật kiểu OpenAI
    re.compile(r"ghp_[A-Za-z0-9]{8,}"),  # PAT cổ điển của GitHub
    re.compile(r"github_pat_[A-Za-z0-9_]{8,}"),  # PAT phân quyền chi tiết của GitHub
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ID
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{8,}"),  # Token của Slack
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),  # Token Bearer
)

_SECRET_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET")
_MIN_SECRET_LEN = 8


class CredentialError(Exception):
    """Ném ra khi thông tin xác thực bắt buộc bị thiếu hoặc rỗng."""


def load_api_key(env_var: str) -> str:
    """Tải một API key từ môi trường.

    Raises
    ------
    CredentialError
        Nếu biến chưa được thiết lập hoặc rỗng sau khi loại bỏ khoảng trắng.
    """
    value = os.environ.get(env_var, "").strip()
    if not value:
        raise CredentialError(
            f"Environment variable '{env_var}' is not set or empty. "
            f"Set it before running the provider."
        )
    return value


def _secret_env_values() -> list[str]:
    """Giá trị nguyên văn của các biến môi trường có dạng bí mật, được đọc tại thời điểm gọi."""
    values = []
    for name, value in os.environ.items():
        if len(value) >= _MIN_SECRET_LEN and name.upper().endswith(_SECRET_SUFFIXES):
            values.append(value)
    return values


def redact(text: str) -> str:
    """Thay thế các chuỗi con có định dạng thông tin xác thực trong *text* bằng ``[REDACTED]``."""
    redacted = text
    for pattern in _FORMAT_RES:
        redacted = pattern.sub("[REDACTED]", redacted)
    for secret in _secret_env_values():
        if secret in redacted:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted
