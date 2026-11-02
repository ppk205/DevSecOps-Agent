"""The host numbers events, refuses a second turn and never decides a gate."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from tests.harness.conftest import make_ctx
from tests.harness.fakes import ScriptedTransport
from vulnscan.harness.host import SessionHost
from vulnscan.harness.messages import Message, Reply, ToolCall, Usage
from vulnscan.harness.session import Session


def reply(
    content: str = "", calls: list[ToolCall] | None = None, usage: Usage | None = None
) -> Reply:
    return Reply(
        Message("assistant", content, calls or []),
        usage or Usage(input_tokens=10, output_tokens=5, cost_usd=0.01, latency_ms=1),
        "fake",
    )


def host_for(
    tmp_path: Path, replies: list[Reply | Exception]
) -> tuple[SessionHost, list[dict[str, Any]]]:
    ctx, _ = make_ctx(tmp_path, [])
    events: list[dict[str, Any]] = []
    host = SessionHost(Session(ScriptedTransport(replies), ctx), events.append)
    return host, events


def test_turn_emits_ordered_events(tmp_path: Path) -> None:
    host, events = host_for(
        tmp_path,
        [
            reply(calls=[ToolCall("c1", "inventory", {"globs": ["**/*.java"]})]),
            reply("done"),
        ],
    )
    assert host.submit("look around") is True
    assert host.wait_idle(10) is True
    host.close()

    types = [event["type"] for event in events]
    assert types[-1] == "done" and events[-1]["reason"] == "completed"
    assert {"tool_call", "tool_result", "usage", "text_delta"} <= set(types)
    assert [event["seq"] for event in events] == list(range(1, len(events) + 1))
    assert all(event["protocol"] == "devsec-chat/1" for event in events)


def test_second_message_while_busy_is_refused(tmp_path: Path) -> None:
    gate = threading.Event()

    class Blocking(ScriptedTransport):
        def complete(
            self, system: str, messages: list[Message], tools: list[dict[str, Any]]
        ) -> Reply:
            gate.wait(10)
            return reply("late")

    ctx, _ = make_ctx(tmp_path, [])
    events: list[dict[str, Any]] = []
    host = SessionHost(Session(Blocking([]), ctx), events.append)
    assert host.submit("first") is True
    assert host.submit("second") is False
    gate.set()
    assert host.wait_idle(10) is True
    host.close()
    errors = [event for event in events if event["type"] == "error"]
    assert errors and errors[-1]["message"] == "a turn is already running"


def test_interrupt_ends_turn_without_running_next_tool(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    ctx, _ = make_ctx(tmp_path, [])
    events: list[dict[str, Any]] = []
    host = SessionHost(
        Session(
            ScriptedTransport(
                [
                    reply(
                        calls=[
                            ToolCall("c1", "inventory", {"globs": ["**/*.java"]}),
                            ToolCall("c2", "grep", {"pattern": "x"}),
                        ]
                    )
                ]
            ),
            ctx,
        ),
        events.append,
    )
    ran: list[str] = []

    def fake_run_tool(context, call):  # type: ignore[no-untyped-def]
        ran.append(call.name)
        host.interrupt()
        return "{}"

    monkeypatch.setattr("vulnscan.harness.session.run_tool", fake_run_tool)
    host.submit("go")
    assert host.wait_idle(10) is True
    host.close()
    assert ran == ["inventory"]
    assert events[-1]["type"] == "done" and events[-1]["reason"] == "completed"
    assert any(
        event["type"] == "text_delta" and event["text"] == "Interrupted." for event in events
    )


def test_events_are_redacted(tmp_path: Path) -> None:
    secret = "sk-ant-" + "x" * 24
    host, events = host_for(tmp_path, [reply(f"key {secret} leaked")])
    host.submit("go")
    assert host.wait_idle(10) is True
    host.close()
    assert secret not in str(events)
    assert "[REDACTED]" in str(events)


def test_done_carries_error_reason(tmp_path: Path) -> None:
    host, events = host_for(tmp_path, [RuntimeError("boom")])
    host.submit("go")
    assert host.wait_idle(10) is True
    host.close()
    assert events[-1]["type"] == "done" and events[-1]["reason"] == "error"
    assert any(event["type"] == "error" for event in events)


@pytest.mark.parametrize("timeout", [0.01])
def test_wait_idle_times_out_while_running(tmp_path: Path, timeout: float) -> None:
    gate = threading.Event()

    class Slow(ScriptedTransport):
        def complete(
            self, system: str, messages: list[Message], tools: list[dict[str, Any]]
        ) -> Reply:
            gate.wait(10)
            return reply("late")

    ctx, _ = make_ctx(tmp_path, [])
    host = SessionHost(Session(Slow([]), ctx), lambda event: None)
    host.submit("go")
    assert host.wait_idle(timeout) is False
    gate.set()
    assert host.wait_idle(10) is True
    host.close()
