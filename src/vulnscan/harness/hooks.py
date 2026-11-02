"""Install, remove and inspect the opt-in git hooks that queue a review.

A hook only appends to the pending queue and exits 0, so a missing interpreter
or a broken queue never blocks a commit. ``install`` refuses to overwrite a
hook it did not write, and names the exact line the user should add instead.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

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
    return (
        "#!/bin/sh\n"
        f"{MARKER}\n"
        f'"{python}" -m vulnscan.harness.pending record --hook {name} '
        '>/dev/null 2>&1 || echo "devsec: could not queue review" >&2\n'
        "exit 0\n"
    )


def _hooks_dir(repo: Path) -> Path:
    hooks = Path(repo) / ".git" / "hooks"
    if not (Path(repo) / ".git").exists():
        raise HookError(f"{repo} is not a git checkout")
    hooks.mkdir(parents=True, exist_ok=True)
    return hooks


def install(repo: Path, python: Path) -> list[str]:
    """Write both hooks; refuse anything that carries a foreign hook."""
    hooks = _hooks_dir(repo)
    written: list[str] = []
    for name in HOOK_NAMES:
        target = hooks / name
        if target.exists() and MARKER not in target.read_text(encoding="utf-8", errors="replace"):
            raise HookError(
                f"{target} exists and was not written by devsec. Add this line to it:\n"
                + MANUAL_LINE.format(python=python, name=name)
            )
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
        if not target.exists():
            continue
        if MARKER in target.read_text(encoding="utf-8", errors="replace"):
            target.unlink()
            removed.append(name)
    return removed


def status(repo: Path) -> dict[str, str]:
    """``installed``, ``foreign`` or ``absent`` for each hook."""
    hooks = _hooks_dir(repo)
    result: dict[str, str] = {}
    for name in HOOK_NAMES:
        target = hooks / name
        if not target.exists():
            result[name] = "absent"
            continue
        text = target.read_text(encoding="utf-8", errors="replace")
        result[name] = "installed" if MARKER in text else "foreign"
    return result


def current_python() -> Path:
    """The interpreter a hook should call: this one, not whatever is on PATH."""
    import sys

    return Path(sys.executable).resolve()


def is_executable(path: Path) -> bool:
    return os.access(path, os.X_OK)
