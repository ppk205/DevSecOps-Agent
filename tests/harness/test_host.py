"""The host numbers events, refuses a second turn and never decides a gate."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from tests.harness.conftest import make_ctx
from tests.harness.fakes import ScriptedTransport
from vulnscan.harness.host import SessionHost
from vulnscan.harness.messages import Message, ProviderError, Reply, ToolCall, Usage
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
    assert events[-1]["type"] == "done" and events[-1]["reason"] == "interrupted"
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
    assert events[-1]["type"] == "done" and events[-1]["reason"] == "failed"
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


def test_provider_failure_emits_error_and_failed_done(tmp_path: Path) -> None:
    host, events = host_for(tmp_path, [ProviderError("HTTP 500")])
    host.submit("go")
    assert host.wait_idle(5)
    assert events[-1]["reason"] == "failed"
    assert any(e["type"] == "error" and "HTTP 500" in e["message"] for e in events)
    host.close()


def test_inflight_reply_is_discarded_but_usage_is_counted(tmp_path: Path) -> None:
    entered, release = threading.Event(), threading.Event()

    class Blocking(ScriptedTransport):
        def complete(self, system, messages, tools):
            entered.set()
            assert release.wait(5)
            return reply("must not appear")

    ctx, _ = make_ctx(tmp_path, [])
    events = []
    host = SessionHost(Session(Blocking([]), ctx), events.append)
    host.submit("go")
    assert entered.wait(5)
    host.interrupt()
    release.set()
    assert host.wait_idle(5)
    assert "must not appear" not in str(events)
    assert ctx.log.totals()["input_tokens"] == 10
    assert events[-1]["reason"] == "interrupted"
    host.close()


def test_tool_results_and_running_totals_are_complete(tmp_path: Path) -> None:
    host, events = host_for(tmp_path, [reply(calls=[ToolCall("x", "unknown", {})]), reply("ok")])
    host.submit("go")
    assert host.wait_idle(5)
    result = next(e for e in events if e["type"] == "tool_result")
    assert "unknown tool" in str(result["result"])
    usage = [e for e in events if e["type"] == "usage"]
    assert usage[-1]["total_tokens"] == 30
    assert usage[-1]["total_cost_usd"] == 0.02
    assert [e["type"] for e in events] == [
        "text_delta",
        "tool_call",
        "tool_result",
        "usage",
        "text_delta",
        "usage",
        "done",
    ]
    assert events[0]["role"] == "user"
    assert host.state()["messages"][0]["content"] == "go"
    host.close()


def test_interrupt_before_worker_enters_send_is_not_lost(tmp_path, monkeypatch):
    host, events = host_for(tmp_path, [reply("should not run")])
    entered, release = threading.Event(), threading.Event()
    original = host.session.send

    def delayed(text):
        entered.set()
        assert release.wait(5)
        return original(text)

    monkeypatch.setattr(host.session, "send", delayed)
    host.submit("go")
    assert entered.wait(5)
    host.interrupt()
    release.set()
    assert host.wait_idle(5)
    assert host.session.transport.calls == []
    assert events[-1]["reason"] == "interrupted"
    host.close()


def test_embedded_host_preserves_a_scripted_asker(tmp_path):
    ctx, asked = make_ctx(tmp_path, ["approve"])
    host = SessionHost(
        Session(
            ScriptedTransport(
                [
                    reply(
                        calls=[
                            ToolCall(
                                "plan", "propose_scan_plan", {"scope": ["A.java"], "classes": []}
                            )
                        ]
                    ),
                    reply("done"),
                ]
            ),
            ctx,
        ),
        lambda event: None,
    )
    try:
        assert host.submit("plan")
        assert host.wait_idle(2)
        assert asked == ["G1"]
        assert ctx.ws.plan == {"scope": ["A.java"], "classes": []}
    finally:
        host.close()
