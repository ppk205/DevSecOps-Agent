"""Scanner binaries are resolved against the application's own environment.

The TUI can be launched from a shell whose PATH has neither the repo venv's
``Scripts`` dir nor any user bin dir. Before this, ``which()`` returned None
for scanners that ship inside the venv, the availability check failed, and
the scan reported "not installed or not present on PATH" with zero findings.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from vulnscan.scanners import platform as platform_module
from vulnscan.scanners import process as process_module
from vulnscan.scanners.platform import which


@pytest.fixture()
def fake_venv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A directory pair shaped like a venv, registered as ``sys.prefix``."""
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path))
    return scripts


def _write_executable(path: Path, body: str = "") -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _binary_name(stem: str) -> str:
    """A resolvable binary name for this platform: PATHEXT is a Windows-only
    mechanism, so POSIX wants the bare name while Windows wants ``.exe``."""
    return f"{stem}.exe" if os.name == "nt" else stem


def test_which_falls_back_to_the_interpreters_venv(
    fake_venv: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = fake_venv / _binary_name("scanner-probe")
    _write_executable(binary)
    monkeypatch.setattr(platform_module.shutil, "which", lambda name: None)

    resolved = which("scanner-probe")
    assert resolved is not None
    assert Path(resolved).samefile(binary)


def test_which_prefers_path_over_the_venv(fake_venv: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_executable(fake_venv / "scanner-probe.exe")
    monkeypatch.setattr(platform_module.shutil, "which", lambda name: "C:/elsewhere/scanner-probe")

    assert which("scanner-probe") == "C:/elsewhere/scanner-probe"


def test_which_returns_none_when_nothing_matches(
    fake_venv: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(platform_module.shutil, "which", lambda name: None)

    assert which("scanner-probe") is None


class _FakeProcess:
    """Minimal Popen stand-in: one successful communicate round."""

    returncode = 0

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    def communicate(
        self, input: str | None = None, timeout: float | None = None
    ) -> tuple[str, str]:
        return "resolved-ok\n", ""

    def poll(self) -> int:
        return 0

    def kill(self) -> None:  # pragma: no cover - the happy path never kills
        pass

    def terminate(self) -> None:  # pragma: no cover - the happy path never kills
        pass


def test_run_command_spawns_the_resolved_path(
    fake_venv: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The spawn must use the resolved absolute path, not the bare name:
    Popen searches only the child's PATH, which need not contain the venv."""
    binary = fake_venv / _binary_name("scanner-probe")
    _write_executable(binary)
    monkeypatch.setattr(platform_module.shutil, "which", lambda name: None)
    spawned: list[list[str]] = []

    def fake_popen(command: list[str], **kwargs: object) -> _FakeProcess:
        spawned.append(list(command))
        return _FakeProcess(**kwargs)

    import subprocess

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    result = process_module.run_command(["scanner-probe", "--flag"], timeout=10)

    assert spawned and Path(spawned[0][0]).samefile(binary)
    assert spawned[0][1] == "--flag"
    assert Path(result.command[0]).samefile(binary)
    assert result.returncode == 0
