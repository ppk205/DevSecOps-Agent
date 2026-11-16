"""Phân tách thông tin xác thực cho các lượt chạy xác minh.

Một tiến trình con xác minh TUYỆT ĐỐI KHÔNG được thấy thông tin xác thực provider và
TUYỆT ĐỐI KHÔNG được kế thừa host docker socket. Module này tạo ra môi trường
đã được làm sạch.
"""

from __future__ import annotations

import os
import re

# Các pattern mà sự hiện diện của chúng sẽ làm rò rỉ thông tin xác thực provider vào
# lượt chạy xác minh. Được so khớp không phân biệt hoa thường với env key.
_SENSITIVE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r".*_API_KEY$",
        r".*_API_SECRET$",
        r".*_TOKEN$",
        r".*_PASSWORD$",
        r".*_PASSWD$",
        r".*_SECRET$",
        r"^OPENAI.*$",
        r"^ANTHROPIC.*$",
        r"^AZURE.*KEY.*$",
        r"^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)$",
        r"^GOOGLE.*KEY.*$",
        r"^GITHUB_TOKEN$",
        r"^GH_TOKEN$",
        r"^HF_TOKEN$",
        r"^OMNIROUTE.*KEY.*$",
        r"^OMNIROUTE.*TOKEN.*$",
    )
]


def _is_sensitive(key: str) -> bool:
    return any(p.search(key) for p in _SENSITIVE_PATTERNS)


def scrub_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Trả về một môi trường đã được loại bỏ thông tin xác thực provider.

    Nếu base là None, bắt đầu từ os.environ (một bản sao, không bao giờ bị thay đổi).
    """
    src = dict(base if base is not None else os.environ)
    scrubbed: dict[str, str] = {}
    removed: list[str] = []
    for k, v in src.items():
        if _is_sensitive(k):
            removed.append(k)
        else:
            scrubbed[k] = v
    scrubbed["_VULNSCAN_SCRUBBED_KEYS"] = ",".join(sorted(removed))
    return scrubbed


def assert_no_credentials(env: dict[str, str]) -> None:
    """Báo lỗi ngay lập tức nếu một credential vẫn xuất hiện trong env."""
    leaked = [k for k in env if _is_sensitive(k) and k != "_VULNSCAN_SCRUBBED_KEYS"]
    if leaked:
        raise AssertionError(f"provider credentials present in env: {sorted(leaked)}")
