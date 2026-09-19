"""Subprocess wrapper for scanner adapters.

Adapters never call ``subprocess`` directly: all external process invocations
funnel through here so tests can monkeypatch one seam (``run_command``) instead
of every adapter, and so timeouts / missing binaries are handled uniformly.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from subprocess import TimeoutExpired
from typing import Sequence

from .platform import normalize_path, which


@dataclass
class CommandResult:
    """Result of an external command invocation."""

    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_ms: int = 0
    command: tuple[str, ...] = field(default_factory=tuple)

    @property
    def succeeded(self) -> bool:
        """True iff the process exited zero without timing out."""
        return self.returncode == 0 and not self.timed_out


def run_command(
    argv: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Run *argv* and capture output.

    Never raises for missing binary, non-zero exit, or timeout — adapters
    translate the returned :class:`CommandResult` into a documented condition.
    """
    import subprocess

    argv = tuple(normalize_path(a) if isinstance(a, str) else a for a in argv)
    command = tuple(str(a) for a in argv)

    full_env: dict[str, str] = dict(os.environ)
    if env:
        full_env.update({k: str(v) for k, v in env.items()})

    start = _now_ms()
    try:
        proc = subprocess.run(  # noqa: S603 — argv built by adapters, not user input
            command,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=full_env,
            input=input_text,
            check=False,
        )
        return CommandResult(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            timed_out=False,
            duration_ms=_now_ms() - start,
            command=command,
        )
    except TimeoutExpired:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=f"command timed out after {timeout}s",
            timed_out=True,
            duration_ms=_now_ms() - start,
            command=command,
        )
    except FileNotFoundError:
        # stdlib may raise FileNotFoundError directly on POSIX exec failure
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=f"command not found: {command[0] if command else ''}",
            timed_out=False,
            duration_ms=_now_ms() - start,
            command=command,
        )


def binary_available(binary: str) -> bool:
    """True iff *binary* exists on PATH (or is an absolute existing path)."""
    return which(binary) is not None


def _binary_path(binary: str) -> str | None:
    return which(binary)


def _now_ms() -> int:
    import time

    return int(time.monotonic() * 1000)


__all__ = [
    "binary_available",
    "CommandResult",
    "run_command",
]
