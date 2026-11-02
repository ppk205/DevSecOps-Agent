"""Optional verified Go compute paths; Python remains the compatible fallback."""

from __future__ import annotations

import atexit
import os
import shutil
from pathlib import Path
from typing import Any

from vulnscan.core.stdio_worker import JSONWorker
from vulnscan.scanners.process import _cancel_check

_workers: dict[str, JSONWorker] = {}


def binary_path(*, required: bool = False) -> str | None:
    if not required and os.environ.get("DEVSECOPS_NATIVE", "auto") == "python":
        return None
    override = os.environ.get("DEVSECOPS_GO_BINARY")
    if override:
        return shutil.which(override)
    name = "devsecops-agent-go.exe" if os.name == "nt" else "devsecops-agent-go"
    local = Path(__file__).resolve().parents[3] / "bin" / name
    return str(local) if local.is_file() else shutil.which(name)


def compute(method: str, params: dict[str, Any]) -> Any:
    binary = binary_path()
    if binary is None:
        return None
    if binary not in _workers:
        _workers[binary] = JSONWorker([binary, "worker"])
        atexit.register(_workers[binary].close)
    try:
        return _workers[binary].call(method, params, 5, _cancel_check.get())
    except (OSError, RuntimeError, ValueError, TimeoutError):
        return None
