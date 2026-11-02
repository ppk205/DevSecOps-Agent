"""The session host: one session, many events, one gate at a time.

The host owns the session and turns its activity into numbered events. A turn
runs on a daemon thread so a client can submit, interrupt and wait for idle.
Every event is redacted before it leaves the host, and every gate decision
still belongs to the Python ``GateKeeper``; the host never decides.
"""

from __future__ import annotations

import itertools
import threading
from collections.abc import Callable
from typing import Any

from vulnscan.providers.credentials import redact_value

from .messages import Message
from .session import Session

PROTOCOL = "devsec-chat/1"
MAX_MEMORY_EVENTS = 5000

Emit = Callable[[dict[str, Any]], None]


class SessionHost:
    """Owns a :class:`Session` and publishes its events."""

    def __init__(self, session: Session, emit: Emit) -> None:
        self.session = session
        self.emit = emit
        self._seq = itertools.count(1)
        self._lock = threading.Lock()
        self._busy = False
        self._idle = threading.Event()
        self._idle.set()
        self._events: list[dict[str, Any]] = []
        self._unsubscribe = session.ctx.log.subscribe(self._on_log)

    # ------------------------------------------------------------------
    # events
    # ------------------------------------------------------------------
    def _publish(self, event: dict[str, Any]) -> dict[str, Any]:
        payload = redact_value(event)
        if not isinstance(payload, dict):
            payload = {"value": payload}
        payload["type"] = str(event.get("type", "event"))
        payload["seq"] = next(self._seq)
        payload["protocol"] = PROTOCOL
        self._events.append(payload)
        if len(self._events) > MAX_MEMORY_EVENTS:
            del self._events[: len(self._events) - MAX_MEMORY_EVENTS]
        self.emit(payload)
        return payload

    def _on_log(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "message":
            message = event.get("message") or {}
            role = message.get("role")
            if role == "assistant":
                content = str(message.get("content", ""))
                if content:
                    self._publish({"type": "text_delta", "text": content})
                for call in message.get("tool_calls") or []:
                    self._publish(
                        {
                            "type": "tool_call",
                            "id": call.get("id"),
                            "name": call.get("name"),
                            "arguments": call.get("arguments"),
                        }
                    )
            elif role == "tool":
                summary = " ".join(str(message.get("content", "")).split())[:120]
                self._publish(
                    {
                        "type": "tool_result",
                        "id": message.get("tool_call_id"),
                        "name": message.get("name"),
                        "summary": summary,
                    }
                )
        elif kind == "usage":
            self._publish(
                {
                    "type": "usage",
                    "provider": event.get("provider"),
                    "model": event.get("model"),
                    "input_tokens": event.get("input_tokens"),
                    "output_tokens": event.get("output_tokens"),
                    "cost_usd": event.get("cost_usd"),
                }
            )
        elif kind == "gate":
            self._publish(
                {
                    "type": "gate_result",
                    "gate": event.get("gate"),
                    "choice": event.get("choice"),
                    "reason": event.get("reason"),
                    "person": event.get("person"),
                    "mode": event.get("mode"),
                }
            )

    def events(self) -> list[dict[str, Any]]:
        """Every event published so far, oldest first."""
        return list(self._events)

    # ------------------------------------------------------------------
    # turns
    # ------------------------------------------------------------------
    @property
    def busy(self) -> bool:
        return self._busy

    def submit(self, text: str) -> bool:
        """Start a turn. False when one is already running."""
        with self._lock:
            if self._busy:
                self._publish({"type": "error", "message": "a turn is already running"})
                return False
            self._busy = True
        self._idle.clear()
        thread = threading.Thread(target=self._run, args=(text,), daemon=True)
        thread.start()
        return True

    def _run(self, text: str) -> None:
        reason = "completed"
        try:
            self.session.send(text)
        except Exception as exc:  # noqa: BLE001 - a turn must not kill the host
            reason = "error"
            self._publish({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
        finally:
            with self._lock:
                self._busy = False
            self._idle.set()
            self._publish({"type": "done", "reason": reason})

    def interrupt(self) -> None:
        """Ask the running turn to stop before its next tool call."""
        self.session.cancel()

    def wait_idle(self, timeout: float) -> bool:
        """Wait for the current turn to finish; False on timeout."""
        return self._idle.wait(timeout)

    def close(self) -> None:
        """Stop listening and end any running turn."""
        self.interrupt()
        self._unsubscribe()
        with self._lock:
            self._busy = False
        self._idle.set()


def message_text(message: Message) -> str:
    """Plain text of a message, for one-line summaries."""
    return " ".join(message.content.split())
