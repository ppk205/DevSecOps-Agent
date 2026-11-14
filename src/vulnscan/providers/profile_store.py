"""Lưu trữ hồ sơ (profile) của provider — file JSON trên đĩa.

Các profile được mã hóa khi lưu trữ trong môi trường production; trong môi trường phát triển, chúng
được lưu dưới dạng file JSON thuần trong thư mục ``.providers/``. API key
được tham chiếu qua tên biến môi trường, không bao giờ lưu trực tiếp trong file profile.
"""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import ValidationError

from vulnscan.contracts.provider import ProviderProfile

logger = logging.getLogger(__name__)

_DEFAULT_DIR = Path(".providers")


def _dir(base: Path | None = None) -> Path:
    d = base or _DEFAULT_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_profile(profile: ProviderProfile, base: Path | None = None) -> Path:
    """Ghi *profile* vào ``<base>/<id>.json``."""
    d = _dir(base)
    path = d / f"{profile.id}.json"
    path.write_text(profile.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_profile(profile_id: str, base: Path | None = None) -> ProviderProfile:
    """Tải một profile đơn lẻ theo ID."""
    d = _dir(base)
    path = d / f"{profile_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Provider profile '{profile_id}' not found at {path}")
    return ProviderProfile.model_validate_json(path.read_text(encoding="utf-8"))


def list_profiles(base: Path | None = None) -> list[ProviderProfile]:
    """Trả về tất cả các profile trong thư mục cơ sở."""
    d = _dir(base)
    profiles = []
    for p in sorted(d.glob("*.json")):
        try:
            profiles.append(ProviderProfile.model_validate_json(p.read_text(encoding="utf-8")))
        except (OSError, ValidationError) as exc:
            logger.warning("Skipping malformed provider profile %s: %s", p.name, exc)
            continue
    return profiles


def delete_profile(profile_id: str, base: Path | None = None) -> bool:
    """Xóa một profile. Trả về True nếu đã xóa thành công."""
    d = _dir(base)
    path = d / f"{profile_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def default_profile(base: Path | None = None) -> ProviderProfile | None:
    """Profile đầu tiên có biến môi trường API-key được thiết lập.

    Dùng để tự động kích hoạt model hunt trong mỗi lần quét: một profile
    được chọn rõ ràng luôn được ưu tiên; đây chỉ là phương án dự phòng khi bên gọi
    không chỉ định profile nào. Trả về None khi không có khóa nào được cấu hình,
    trong trường hợp đó các giai đoạn hunt sẽ bỏ qua kèm lý do thay vì thất bại.
    """
    import os

    if base is None and os.environ.get("PYTEST_CURRENT_TEST"):
        # Unit test không bao giờ được truy cập mạng: nếu không có thư mục cơ sở
        # rõ ràng thì sẽ không có provider tự động dưới pytest. Các test kiểm thử
        # chính cơ chế phân giải sẽ truyền base=tmp_path một cách rõ ràng.
        return None
    keyed = [
        p
        for p in list_profiles(base)
        if p.api_key_env and os.environ.get(p.api_key_env, "").strip()
    ]
    if not keyed:
        return None
    keyed.sort(key=lambda p: (0 if p.id == "opencode-free" else 1, p.id))
    return keyed[0]
