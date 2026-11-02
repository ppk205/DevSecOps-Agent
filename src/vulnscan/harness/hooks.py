"""Install, remove and inspect the opt-in git hooks that queue a review.

A hook only appends to the pending queue and exits 0, so a missing interpreter
or a broken queue never blocks a commit. ``install`` refuses to overwrite a
hook it did not write, and names the exact line the user should add instead.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from vulnscan.harness.pending import hooks_directory, plain_path

MARKER = "# devsec-hook v1"
HOOK_NAMES = ("post-commit", "post-merge")
MANUAL_LINE = (
    '"{python}" -m vulnscan.harness.pending record --hook {name} '
    '>/dev/null 2>&1 || echo "devsec: could not queue review" >&2'
)


class HookError(Exception):
    """A hook could not be installed or removed."""


def hook_body(name: str, python: Path) -> str:
    """The exact hook text, with LF endings so git can run it."""
    if name not in HOOK_NAMES:
        raise HookError("unknown hook name")
    line = _manual_line(name, python)
    return f"#!/bin/sh\n{MARKER}\n{line}\nexit 0\n"


def _manual_line(name: str, python: Path) -> str:
    value = python.absolute().as_posix()
    if "\n" in value or "\r" in value or "\x00" in value:
        raise HookError("invalid interpreter path")
    for char in ("\\", '"', "$", "`"):
        value = value.replace(char, "\\" + char)
    return MANUAL_LINE.format(python=value, name=name)


def _hooks_dir(repo: Path) -> Path:
    try:
        return hooks_directory(Path(repo))
    except (ValueError, OSError) as exc:
        raise HookError(str(exc)) from exc


def _hook_status(target: Path) -> str:
    try:
        plain_path(target)
    except (ValueError, OSError):
        return "foreign"
    if not target.exists():
        return "absent"
    if not target.is_file():
        return "foreign"
    text = target.read_text(encoding="utf-8", errors="replace")
    return "installed" if MARKER in text.splitlines() else "foreign"


def install(repo: Path, python: Path) -> list[str]:
    """Write both hooks; refuse anything that carries a foreign hook."""
    hooks = _hooks_dir(repo)
    written: list[str] = []
    for name in HOOK_NAMES:
        target = hooks / name
        if _hook_status(target) == "foreign":
            raise HookError(
                f"{target} exists and was not written by devsec. Add this line to it:\n"
                + _manual_line(name, python)
            )
    hooks.mkdir(parents=True, exist_ok=True)
    for name in HOOK_NAMES:
        target = hooks / name
        target.write_text(hook_body(name, python), encoding="utf-8", newline="\n")
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        written.append(name)
    return written


def uninstall(repo: Path) -> list[str]:
    """Remove only hooks that carry the marker."""
    hooks = _hooks_dir(repo)
    removed: list[str] = []
    for name in HOOK_NAMES:
        target = hooks / name
        if _hook_status(target) == "installed":
            target.unlink()
            removed.append(name)
    return removed


def status(repo: Path) -> dict[str, str]:
    """``installed``, ``foreign`` or ``absent`` for each hook."""
    hooks = _hooks_dir(repo)
    result: dict[str, str] = {}
    for name in HOOK_NAMES:
        target = hooks / name
        result[name] = _hook_status(target)
    return result


def current_python() -> Path:
    """The interpreter a hook should call: this one, not whatever is on PATH."""
    import sys

    return Path(sys.executable).resolve()


def is_executable(path: Path) -> bool:
    return os.access(path, os.X_OK)
