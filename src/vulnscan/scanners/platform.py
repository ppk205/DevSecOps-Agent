"""Cross-platform path and binary helpers.

Windows/MSYS quoting differs from POSIX; adapters route path arguments
through ``normalize_path`` so tests and runtime agree on separators.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def which(binary: str) -> str | None:
    """``shutil.which`` with a venv-relative fallback.

    The scanners ship inside the application's own virtualenv (semgrep via
    the ``scanners`` extra, gitleaks alongside it), but a caller's PATH does
    not necessarily include ``<venv>/Scripts`` — e.g. when the TUI is started
    from a shell that never activated the environment. Without the fallback
    every scanner reports "not found on PATH" and the scan silently produces
    zero findings. Resolution order: PATH first (an explicitly configured
    install wins), then the interpreter's own environment (``sys.prefix``).
    """
    if not binary:
        return None
    if os.path.isabs(binary) or Path(binary).drive:
        # Absolute / drive-qualified: check the file itself.
        p = Path(binary)
        if p.is_file():
            return str(p)
        # Windows: respect PATHEXT for bare absolute names.
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
    """Candidate file names for *binary* inside *directory* (``.exe`` on Windows)."""
    names = [directory / binary]
    for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
        if ext:
            names.append((directory / binary).with_suffix(ext))
    return names


def normalize_path(path: str | os.PathLike[str]) -> str:
    """Normalize a path to the platform-native form.

    Adapters receive repo-relative POSIX-ish paths from the scan spec; the
    scanner binaries run natively (Windows) and need native separators.
    """
    return os.fspath(path).replace("/", os.sep) if os.sep != "/" else os.fspath(path)


def repo_relative(path: str, root: str) -> str:
    """Best-effort conversion of *path* to a repo-relative POSIX path.

    Never raises: un-resolvable paths are returned unchanged so the caller can
    decide whether to record them as-is or reject the observation.
    """
    try:
        p = Path(path)
        root_p = Path(root)
        if p.is_absolute():
            try:
                rel = p.relative_to(root_p)
                return rel.as_posix()
            except ValueError:
                # Absolute but not under root: keep tail beyond the root name.
                return p.as_posix().lstrip("/")
        merged = (root_p / p).resolve(strict=False)
        try:
            return merged.relative_to(root_p.resolve(strict=False)).as_posix()
        except ValueError:
            return p.as_posix().lstrip("/")
    except (OSError, RuntimeError, ValueError):
        return path.replace("\\", "/")


def iter_files(root: str | os.PathLike[str], suffixes: tuple[str, ...]) -> list[str]:
    """Return sorted POSIX repo-relative file paths under *root*.

    Hidden directories (``.git``, ``target``-like build dirs) are skipped so
    coverage records describe source inventory, not build artifacts.
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
    """Read a file as text; returns '' on any read failure."""
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
