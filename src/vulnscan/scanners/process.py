"""Subprocess wrapper for scanner adapters.

Adapters never call ``subprocess`` directly: all external process invocations
funnel through here so tests can monkeypatch one seam (``run_command``) instead
of every adapter, and so timeouts / missing binaries are handled uniformly.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from subprocess import TimeoutExpired

from .platform import which


class ScanCancelled(BaseException):
    """Cooperative cancellation must not be swallowed by adapter error handlers."""


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
    }
    return {k: v for k, v in {**os.environ, **(extra or {})}.items() if k.upper() in allowed}


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

    command = tuple(str(a) for a in argv)

    full_env = scanner_environment(env)
    home = tempfile.TemporaryDirectory(prefix="vulnscan-home-")
    full_env.update(
        HOME=home.name, USERPROFILE=home.name, XDG_CONFIG_HOME=home.name, XDG_CACHE_HOME=home.name
    )
    start = _now_ms()
    proc = None
    stopping = False
    try:
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
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
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
            if os.name == "nt":
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
    """True iff *binary* exists on PATH (or is an absolute existing path)."""
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
