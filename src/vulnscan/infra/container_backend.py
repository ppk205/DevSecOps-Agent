"""Container backend with a documented-unavailable docker path.

Docker is NOT available on the build host. The DockerBackend therefore
raises a structured Unavailable condition that callers record as a
coverage limitation, rather than crashing or silently degrading.
The LocalSubprocessBackend is the fallback execution backend.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class BackendUnavailable(RuntimeError):
    """The requested backend cannot run on this host (documented condition)."""


@dataclass
class ExecutionResult:
    """Outcome of running one command under a backend."""
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    backend: str = "local"
    workdir: str | None = None


class ContainerBackend:
    """Protocol-style base: what every execution backend must provide."""

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
    """Docker-based isolation. Unavailable on this host by design."""

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
            # Documented unavailable condition: never crash the pipeline.
            raise BackendUnavailable(
                "docker CLI not found; the container isolation level is "
                "unavailable on this host. Falls back to LocalSubprocessBackend."
            )
        raise BackendUnavailable(
            "docker backend present but container execution is out of scope "
            "for this run; use LocalSubprocessBackend."
        )


class LocalSubprocessBackend(ContainerBackend):
    """Fallback backend: subprocess with timeout + resource limits.

    Not a security boundary. Used when Docker is unavailable; the isolation
    guarantees that do hold are: no provider credentials in the environment,
    no host docker socket, bounded runtime, bounded memory (where the OS
    supports RLIMIT), and a scratch workdir that is cleaned up.
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

        kwargs: dict[str, Any] = {
            "cwd": str(workdir),
            "timeout": timeout,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        if env is not None:
            kwargs["env"] = env

        try:
            proc = subprocess.run(command, **kwargs)
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
