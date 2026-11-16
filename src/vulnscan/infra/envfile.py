"""Quản lý file ``.env`` cục bộ của dự án cho API key và cài đặt provider.

Các key nằm trong môi trường tiến trình (không bao giờ nhúng vào báo cáo hoặc bản ghi
tra cứu của model). Helper này lưu chúng vào một file ``.env`` được gitignore để
người dùng lần đầu có thể lưu key một lần thay vì phải export ở mỗi phiên shell.

Ghi chú bảo mật:

- File ``.env`` được tạo với quyền chỉ dành cho chủ sở hữu (0600 trên POSIX).
- Các giá trị không bao giờ được log; :func:`mask_secret` hiển thị placeholder an toàn.
- Các giá trị môi trường tiến trình hiện có luôn được ưu tiên hơn file, nhờ đó việc chèn
  secret trong CI tiếp tục hoạt động bình thường.
"""

from __future__ import annotations

import os
from pathlib import Path

_ENV_FILENAME = ".env"
_FILE_LOADED_VALUES: dict[tuple[str, str], str] = {}


def mask_secret(value: str) -> str:
    """Trả về placeholder hiển thị an toàn không bao giờ chứa giá trị thực."""
    if not value:
        return ""
    return "•••••••• (saved)"


def find_project_root(start: Path | str | None = None) -> Path:
    """Duyệt ngược từ *start* lên thư mục chứa ``pyproject.toml``.

    Dự phòng bằng thư mục làm việc hiện tại khi không tìm thấy tệp đánh dấu
    (ví dụ: bản cài đặt portable không theo cấu trúc repo).
    """
    current = Path(start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return Path.cwd().resolve()


class EnvFile:
    """Trình đọc/ghi định dạng ``KEY=value`` tối giản cho file ``.env`` của dự án.

    Chỉ cấu trúc phẳng ``KEY=value`` được quản lý; các chú thích và dòng trống
    được giữ nguyên vẹn. Các giá trị có khoảng trắng hoặc ký tự ``#`` được đặt trong dấu ngoặc kép.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        if path is None:
            path = find_project_root() / _ENV_FILENAME
        self.path = Path(path)

    def get(self, name: str) -> str | None:
        for key, value in self._read_pairs():
            if key == name:
                return value
        return None

    def names(self) -> list[str]:
        return [key for key, _ in self._read_pairs()]

    def is_configured(self, name: str) -> bool:
        value = os.environ.get(name, "").strip()
        if value:
            return True
        stored = self.get(name)
        return bool(stored and stored.strip())

    def set(self, name: str, value: str) -> Path:
        name = name.strip().upper().replace("-", "_")
        if not name.replace("_", "").isalnum() or not name:
            raise ValueError(f"Invalid environment variable name: {name!r}")
        value = value.strip()
        if not value:
            raise ValueError("Refusing to store an empty secret")
        lines = self._read_lines()
        rendered = f"{name}={_quote(value)}"
        for index, line in enumerate(lines):
            if _split_pair(line)[0] == name:
                lines[index] = rendered
                break
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(rendered + "\n")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("".join(lines), encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.path, 0o600)
        identity = (str(self.path.resolve()), name)
        previous = _FILE_LOADED_VALUES.get(identity)
        if previous is not None and os.environ.get(name) == previous:
            os.environ[name] = value
            _FILE_LOADED_VALUES[identity] = value
        return self.path

    def load_into_environ(self) -> list[str]:
        """Sao chép các key đã lưu vào ``os.environ`` mà không ghi đè nó."""
        loaded: list[str] = []
        for key, value in self._read_pairs():
            if key and value and key not in os.environ:
                os.environ[key] = value
                _FILE_LOADED_VALUES[(str(self.path.resolve()), key)] = value
                loaded.append(key)
        return loaded

    # -- các hàm nội bộ -------------------------------------------------

    def _read_lines(self) -> list[str]:
        if not self.path.is_file():
            return []
        return self.path.read_text(encoding="utf-8").splitlines(keepends=True)

    def _read_pairs(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for line in self._read_lines():
            key, value = _split_pair(line)
            if key:
                pairs.append((key, value))
        return pairs


def _split_pair(line: str) -> tuple[str, str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return "", ""
    key, _, raw = stripped.partition("=")
    key = key.strip()
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    elif len(value) >= 2 and value[0] == value[-1] == "'":
        value = value[1:-1]
    comment_split = value.split(" #", 1)
    if not (raw.strip().startswith(('"', "'"))):
        value = comment_split[0].strip()
    if not key.replace("_", "").isalnum():
        return "", ""
    return key, value


def _quote(value: str) -> str:
    if any(ch in value for ch in (" ", "#", '"', "'")):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value
