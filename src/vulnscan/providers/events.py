"""Per-run model progress; observers do not change model or tool permissions."""

from collections.abc import Callable
from contextvars import ContextVar
from typing import Any

from .credentials import redact

model_progress: ContextVar[Callable[[dict[str, Any]], None] | None] = ContextVar(
    "model_progress", default=None
)


def emit_model_event(kind: str, status: str, message: str, **details: Any) -> None:
    observer = model_progress.get()
    if observer is not None:
        observer({"kind": kind, "status": status, "message": redact(message), **details})
