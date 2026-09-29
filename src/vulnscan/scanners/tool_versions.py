"""Lightweight helpers for probing tool versions and building argument lists."""

from __future__ import annotations

from typing import Any

from vulnscan.contracts import ScanSpecification

from .platform import which
from .process import run_command


def probe_version(binary: str) -> str | None:
    """Try ``<binary> --version`` (or ``-version``) and return the first line.

    Returns ``None`` when the binary is absent or does not respond.
    """
    resolved = which(binary)
    if resolved is None:
        return None
    for flag in ("--version", "-version"):
        result = run_command((binary, flag), timeout=10)
        if result.succeeded and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    return None


def java_target_classpath(spec: ScanSpecification) -> str | None:
    """Return the compiled ``classes/`` directory path if present.

    SpotBugs requires compiled bytecode; this helper finds it under the
    standard Maven layout rooted at ``<repo>/target/classes``.
    """
    path = spec.metadata.get("build_artifacts", {}).get("classes_dir")
    return str(path) if path else None


def classpath_from_options(tool_cfg: Any) -> str | None:
    """Pull ``classpath`` from per-tool options, or return ``None``."""
    if tool_cfg is None:
        return None
    return getattr(tool_cfg, "options", {}).get("classpath")


__all__ = ["classpath_from_options", "java_target_classpath", "probe_version"]
