"""Các helper đường dẫn và binary đa nền tảng.

Quy tắc đặt dấu ngoặc kép trên Windows/MSYS khác với POSIX; các adapter điều hướng đối số đường dẫn
qua ``normalize_path`` để test và runtime thống nhất về dấu phân cách.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def which(binary: str) -> str | None:
    """``shutil.which`` với cơ chế dự phòng tương đối theo venv.

    Các scanner được đóng gói bên trong virtualenv riêng của ứng dụng (semgrep thông
    qua extra ``scanners``, gitleaks đi kèm), nhưng PATH của bên gọi không nhất thiết
    phải chứa ``<venv>/Scripts`` — ví dụ khi TUI được khởi chạy từ shell chưa từng
    kích hoạt môi trường. Nếu không có cơ chế dự phòng, mọi scanner sẽ báo "not found on PATH"
    và lượt scan âm thầm không tạo ra finding nào. Thứ tự phân giải: PATH trước (cài đặt
    được cấu hình rõ ràng được ưu tiên), sau đó đến môi trường riêng của trình thông dịch (``sys.prefix``).
    """
    if not binary:
        return None
    if os.path.isabs(binary) or Path(binary).drive:
        # Đường dẫn tuyệt đối / có chỉ định ổ đĩa: kiểm tra chính file đó.
        p = Path(binary)
        if p.is_file():
            return str(p)
        # Windows: tuân thủ PATHEXT cho các tên tuyệt đối không có phần mở rộng.
        for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
            if (p.with_suffix(ext)).is_file():
                return str(p.with_suffix(ext))
        return None
    found = shutil.which(binary)
    if found:
        return found
    import sys

    prefixes = [sys.prefix]
    base_prefix = getattr(sys, "base_prefix", sys.prefix)
    if base_prefix != sys.prefix:
        prefixes.append(base_prefix)
    for prefix in prefixes:
        for candidate in _binary_candidates(Path(prefix) / "Scripts", binary) + _binary_candidates(
            Path(prefix) / "bin", binary
        ):
            if candidate.is_file():
                return str(candidate)
    return None


def _binary_candidates(directory: Path, binary: str) -> list[Path]:
    """Các tên file ứng viên cho *binary* bên trong *directory* (``.exe`` trên Windows)."""
    names = [directory / binary]
    for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
        if ext:
            names.append((directory / binary).with_suffix(ext))
    return names


def normalize_path(path: str | os.PathLike[str]) -> str:
    """Chuẩn hóa một đường dẫn về dạng gốc của nền tảng.

    Các adapter nhận đường dẫn kiểu POSIX tương đối so với repo từ scan spec; các
    binary của scanner chạy ở dạng gốc (Windows) và cần dấu phân cách gốc của hệ thống.
    """
    return os.fspath(path).replace("/", os.sep) if os.sep != "/" else os.fspath(path)


def repo_relative(path: str, root: str) -> str:
    """Chuyển đổi nỗ lực tối đa *path* thành đường dẫn POSIX tương đối so với repo.

    Không bao giờ ném ngoại lệ: các đường dẫn không phân giải được sẽ được trả về nguyên trạng để bên
    gọi quyết định ghi nhận chúng như hiện tại hay từ chối observation.
    """
    try:
        p = Path(path)
        root_p = Path(root)
        if p.is_absolute():
            try:
                rel = p.relative_to(root_p)
                return rel.as_posix()
            except ValueError:
                # Tuyệt đối nhưng không nằm dưới root: giữ lại phần đuôi ngoài tên root.
                return p.as_posix().lstrip("/")
        merged = (root_p / p).resolve(strict=False)
        try:
            return merged.relative_to(root_p.resolve(strict=False)).as_posix()
        except ValueError:
            return p.as_posix().lstrip("/")
    except (OSError, RuntimeError, ValueError):
        return path.replace("\\", "/")


def iter_files(root: str | os.PathLike[str], suffixes: tuple[str, ...]) -> list[str]:
    """Trả về các đường dẫn file POSIX đã sắp xếp tương đối so với repo dưới *root*.

    Các thư mục ẩn (``.git``, thư mục build dạng ``target``) bị bỏ qua để
    các bản ghi coverage mô tả danh mục mã nguồn, không phải artifact build.
    """
    root_p = Path(root)
    skip_dirs = {".git", ".svn", ".hg", "target", "node_modules", ".idea", ".vscode"}
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_p):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for name in sorted(filenames):
            if name.lower().endswith(tuple(s.lower() for s in suffixes)):
                full = Path(dirpath) / name
                try:
                    rel = full.relative_to(root_p).as_posix()
                except ValueError:
                    continue
                out.append(rel)
    return sorted(out)


def read_text(path: str | os.PathLike[str], max_bytes: int = 1_000_000) -> str:
    """Đọc file dưới dạng văn bản; trả về '' khi có bất kỳ lỗi đọc nào."""
    try:
        data = Path(path).read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except (OSError, TypeError, ValueError):
        return ""


__all__ = [
    "iter_files",
    "normalize_path",
    "read_text",
    "repo_relative",
    "which",
]
