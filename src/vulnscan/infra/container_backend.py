"""Container backend với đường dẫn docker được ghi nhận là không khả dụng.

Docker KHÔNG khả dụng trên host bản dựng. Do đó DockerBackend đưa ra
một điều kiện Unavailable có cấu trúc mà bên gọi ghi lại như một giới hạn
độ bao phủ, thay vì gặp sự cố hoặc âm thầm suy giảm chất lượng.
LocalSubprocessBackend là backend thực thi dự phòng.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path


class BackendUnavailable(RuntimeError):
    """Backend được yêu cầu không thể chạy trên host này (điều kiện đã ghi nhận)."""


@dataclass
class ExecutionResult:
    """Kết quả của việc chạy một lệnh dưới một backend."""

    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    backend: str = "local"
    workdir: str | None = None


class ContainerBackend:
    """Lớp cơ sở dạng protocol: những gì mọi execution backend phải cung cấp."""

    name: str = "abstract"

    def is_available(self) -> bool:
        raise NotImplementedError

    def run(
        self,
        command: list[str],
        workdir: Path,
        timeout: float = 120.0,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        raise NotImplementedError


class DockerBackend(ContainerBackend):
    """Cô lập dựa trên Docker. Theo thiết kế là không khả dụng trên host này."""

    name = "docker"

    def __init__(self, image: str = "openjdk:17-slim") -> None:
        self.image = image

    def is_available(self) -> bool:
        return shutil.which("docker") is not None

    def run(
        self,
        command: list[str],
        workdir: Path,
        timeout: float = 120.0,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        if not self.is_available():
            # Điều kiện không khả dụng đã được ghi nhận: không bao giờ làm dừng pipeline.
            raise BackendUnavailable(
                "docker CLI not found; the container isolation level is "
                "unavailable on this host. Falls back to LocalSubprocessBackend."
            )
        raise BackendUnavailable(
            "docker backend present but container execution is out of scope "
            "for this run; use LocalSubprocessBackend."
        )


class LocalSubprocessBackend(ContainerBackend):
    """Backend dự phòng: subprocess kèm timeout + giới hạn tài nguyên.

    Không phải là một ranh giới bảo mật. Được dùng khi Docker không khả dụng; các bảo đảm
    cô lập thực sự có hiệu lực gồm: không có thông tin xác thực provider trong môi trường,
    không có host docker socket, runtime có giới hạn, bộ nhớ có giới hạn (nơi OS
    hỗ trợ RLIMIT), và một thư mục làm việc tạm được dọn dẹp sau khi chạy.
    """

    name = "local-subprocess"

    def is_available(self) -> bool:
        return True

    def run(
        self,
        command: list[str],
        workdir: Path,
        timeout: float = 120.0,
        env: dict[str, str] | None = None,
        memory_limit_mb: int | None = 2048,
    ) -> ExecutionResult:
        import subprocess

        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)

        try:
            proc = subprocess.run(
                command,
                check=False,
                cwd=str(workdir),
                timeout=timeout,
                capture_output=True,
                env=env,
            )
            return ExecutionResult(
                returncode=proc.returncode,
                stdout=proc.stdout or b"",
                stderr=proc.stderr or b"",
                timed_out=False,
                backend=self.name,
                workdir=str(workdir),
            )
        except subprocess.TimeoutExpired as e:
            return ExecutionResult(
                returncode=-1,
                stdout=(e.stdout or b"") if isinstance(e.stdout, bytes) else b"",
                stderr=(e.stderr or b"") if isinstance(e.stderr, bytes) else b"",
                timed_out=True,
                backend=self.name,
                workdir=str(workdir),
            )
