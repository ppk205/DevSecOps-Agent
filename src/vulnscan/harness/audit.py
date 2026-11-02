"""Append-only session log (JSONL) with resume and totals.

One line per event. A session file is the audit trail: messages for resume,
gate decisions for the report, usage for cost. Never rewritten.
"""

from __future__ import annotations

import json
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.providers.credentials import redact_json, redact_value

from .messages import Message


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def new_session_path(root: Path = Path(".devsec/sessions")) -> Path:
    """A fresh ``<root>/<UTC stamp>-<6 hex>.jsonl`` path with the parent created."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    for _ in range(100):
        candidate = root / f"{datetime.now(UTC):%Y%m%dT%H%M%S}-{secrets.token_hex(3)}.jsonl"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not allocate a unique session file under {root}")


class SessionLog:
    """Append-only event log for one session."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self._listener_failures = 0
        # The host shares this reentrant lock so log callbacks and publication
        # have one ordering, without a log-lock/event-lock inversion.
        self.lock = threading.RLock()

    def subscribe(self, fn: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        """Call *fn* after each line is written; the return value unsubscribes."""
        with self.lock:
            self._listeners.append(fn)

        def unsubscribe() -> None:
            with self.lock:
                if fn in self._listeners:
                    self._listeners.remove(fn)

        return unsubscribe

    def append(self, event: dict[str, Any]) -> None:
        payload = redact_value(dict(event))
        payload.setdefault("at", _now_iso())
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(redact_json(payload) + "\n")
                handle.flush()
            for listener in list(self._listeners):
                try:
                    listener(payload)
                except Exception:  # noqa: BLE001 - a listener must never break the loop
                    self._listener_failures += 1

    def events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if not line.strip():
                continue
            try:
                raw: Any = json.loads(line)
            except ValueError:
                # A crash can leave a half-written last line; it is not an event.
                continue
            if isinstance(raw, dict):
                events.append(raw)
        return events

    def messages(self) -> list[Message]:
        messages: list[Message] = []
        for event in self.events():
            kind = event.get("type")
            if kind == "clear":
                messages = []
                continue
            if kind != "message":
                continue
            raw = event.get("message")
            if isinstance(raw, dict):
                messages.append(Message.from_dict(raw))
        return messages

    def totals(self) -> dict[str, float]:
        totals: dict[str, float] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
            "turns": 0,
        }
        for event in self.events():
            if event.get("type") != "usage":
                continue
            totals["input_tokens"] += int(event.get("input_tokens") or 0)
            totals["output_tokens"] += int(event.get("output_tokens") or 0)
            totals["cost_usd"] += float(event.get("cost_usd") or 0.0)
            totals["turns"] += 1
        return totals


__all__ = ["SessionLog", "new_session_path"]
