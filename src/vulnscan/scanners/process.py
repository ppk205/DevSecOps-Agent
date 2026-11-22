"""Wrapper subprocess cho các scanner adapter.

Các adapter không bao giờ gọi trực tiếp ``subprocess``: mọi lệnh gọi tiến trình ngoài
đều được dẫn qua đây để test có thể monkeypatch một điểm nối duy nhất (``run_command``)
thay vì từng adapter, đồng thời xử lý timeout / thiếu binary một cách đồng nhất.
"""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from subprocess import TimeoutExpired

from .platform import which


class ScanCancelled(BaseException):
    """Cơ chế hủy hợp tác không được phép bị nuốt bởi các trình xử lý lỗi của adapter."""


_cancel_check: ContextVar[Callable[[], bool]] = ContextVar("cancel", default=lambda: False)


def scanner_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    allowed = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "HOME",
        "USERPROFILE",
        "SEMGREP_ENABLE_VERSION_CHECK",
        "SEMGREP_SEND_METRICS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
    }
    return {k: v for k, v in {**os.environ, **(extra or {})}.items() if k.upper() in allowed}


@dataclass
class CommandResult:
    """Kết quả của một lần gọi lệnh bên ngoài."""

    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_ms: int = 0
    command: tuple[str, ...] = field(default_factory=tuple)

    @property
    def succeeded(self) -> bool:
        """True nếu và chỉ nếu tiến trình kết thúc với mã 0 mà không bị timeout."""
        return self.returncode == 0 and not self.timed_out


def run_command(
    argv: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Chạy *argv* và thu nhận output.

    Không bao giờ ném ngoại lệ khi thiếu binary, exit code khác 0, hoặc timeout — các
    adapter sẽ dịch :class:`CommandResult` trả về thành điều kiện được ghi nhận tài liệu.
    """
    import subprocess

    command = tuple(str(a) for a in argv)
    # Phân giải file thực thi qua hàm tra cứu dùng chung trước khi spawn: môi trường
    # con truyền PATH của bên gọi xuống nguyên vẹn, và PATH đó không
    # nhất thiết chứa venv mà các scanner được cài đặt cùng. Nếu không có điều này, một
    # scanner mà `which()` nhìn thấy vẫn bị lỗi "command not found" vào thời điểm
    # spawn (exit 127), vì Popen chỉ tìm kiếm trong PATH của tiến trình con.
    resolved = which(command[0])
    if resolved is not None:
        command = (resolved, *command[1:])

    full_env = scanner_environment(env)
    home = tempfile.TemporaryDirectory(prefix="vulnscan-home-")
    full_env.update(
        HOME=home.name, USERPROFILE=home.name, XDG_CONFIG_HOME=home.name, XDG_CACHE_HOME=home.name
    )
    start = _now_ms()
    proc = None
    stopping = False
    try:
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_text else subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=full_env,
            start_new_session=sys.platform != "win32",
            creationflags=creationflags,
        )
        first = True
        while True:
            if _cancel_check.get()():
                raise ScanCancelled()
            if timeout is not None and _now_ms() - start > timeout * 1000:
                raise TimeoutExpired(command, timeout)
            try:
                stdout, stderr = proc.communicate(input=input_text if first else None, timeout=0.1)
                return CommandResult(
                    proc.returncode,
                    stdout or "",
                    stderr or "",
                    duration_ms=_now_ms() - start,
                    command=command,
                )
            except TimeoutExpired:
                first = False
    except (KeyboardInterrupt, ScanCancelled):
        stopping = True
        raise
    except TimeoutExpired:
        stopping = True
        return CommandResult(
            -1,
            stderr=f"command timed out after {timeout}s",
            timed_out=True,
            duration_ms=_now_ms() - start,
            command=command,
        )
    except FileNotFoundError:
        return CommandResult(127, stderr=f"command not found: {command[0]}", command=command)
    finally:
        if proc is not None and (proc.poll() is None or stopping):
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                )
            else:
                import signal

                kill_group = getattr(os, "killpg")  # noqa: B009
                kill_signal = getattr(signal, "SIGKILL")  # noqa: B009
                try:
                    kill_group(proc.pid, kill_signal)
                except ProcessLookupError:
                    pass
            proc.kill()
            proc.communicate()
        home.cleanup()


def binary_available(binary: str) -> bool:
    """True nếu và chỉ nếu *binary* tồn tại trong PATH (hoặc là một đường dẫn tuyệt đối đang tồn tại)."""
    return which(binary) is not None


def _binary_path(binary: str) -> str | None:
    return which(binary)


def _now_ms() -> int:
    import time

    return int(time.monotonic() * 1000)


__all__ = [
    "CommandResult",
    "binary_available",
    "run_command",
]
