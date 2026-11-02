"""Real gate waits with simultaneous clients and durable event replay."""

import hashlib
import threading

import pytest

from tests.harness.conftest import make_ctx
from tests.harness.fakes import ScriptedTransport
from vulnscan.harness.gates import Gate, GateRequest
from vulnscan.harness.host import SessionHost
from vulnscan.harness.session import Session


def make_host(tmp_path, mode="ask"):
    ctx, _ = make_ctx(tmp_path, [], mode=mode)
    events = []
    arrived = threading.Event()

    def emit(event):
        events.append(event)
        if event["type"] == "permission_request":
            arrived.set()

    host = SessionHost(Session(ScriptedTransport([]), ctx), emit)
    return host, events, arrived


def ask(host, arrived, gate=Gate.G6_FIX):
    result = []
    arrived.clear()
    worker = threading.Thread(
        target=lambda: result.append(
            host.session.ctx.gates.ask(GateRequest(gate, "Review", "", {"diff": "whole diff"}))
        )
    )
    worker.start()
    assert arrived.wait(5)
    return worker, result, host.state()["pending"]["request_id"]


def test_first_reply_wins(tmp_path):
    host, events, arrived = make_host(tmp_path)
    host.attach("one", "web")
    host.attach("two", "tui")
    worker, decisions, request_id = ask(host, arrived, Gate.G3_TRIAGE)
    barrier = threading.Barrier(3)
    replies = []

    def answer(client):
        barrier.wait()
        replies.append(host.reply(client, {"request_id": request_id, "choice": "approve"}))

    threads = [threading.Thread(target=answer, args=(client,)) for client in ["one", "two"]]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(5)
    worker.join(5)
    assert sum(r["ok"] for r in replies) == 1
    assert "already answered by" in next(r["error"] for r in replies if not r["ok"])
    gates = [e for e in host.session.ctx.log.events() if e["type"] == "gate"]
    assert len(gates) == 1 and gates[0]["request_id"] == request_id
    assert decisions[0].approved
    assert next(e for e in events if e["type"] == "gate_result")["request_id"] == request_id
    host.close()


@pytest.mark.parametrize(
    "kind,confirm,expected",
    [("web", None, "undecided"), ("web", "apply", "apply"), ("tui", None, "apply")],
)
def test_dangerous_web_reply_needs_confirmation_word(tmp_path, kind, confirm, expected):
    host, _, arrived = make_host(tmp_path)
    host.attach("cookie", kind)
    worker, decisions, request_id = ask(host, arrived)
    assert host.reply("cookie", {"request_id": request_id, "choice": "apply", "confirm": confirm})[
        "ok"
    ]
    worker.join(5)
    assert decisions[0].choice == expected
    person = "tui" if kind == "tui" else "web:" + hashlib.sha256(b"cookie").hexdigest()[:8]
    assert decisions[0].person == person
    if expected == "undecided":
        assert decisions[0].reason == "confirmation word missing"
    host.close()


def test_disconnect_resolves_pending_without_approving(tmp_path):
    host, _, arrived = make_host(tmp_path)
    detach = host.attach("client", "tui")
    worker, decisions, _ = ask(host, arrived)
    detach()
    worker.join(5)
    assert not worker.is_alive()
    assert not decisions[0].approved
    assert host.state()["pending"] is None
    host.close()


def test_events_after_spans_memory_and_log(tmp_path, monkeypatch):
    monkeypatch.setattr("vulnscan.harness.host.MAX_MEMORY_EVENTS", 3)
    host, _, _ = make_host(tmp_path)
    for i in range(8):
        host.publish({"type": "text_delta", "text": str(i)})
    assert [e["seq"] for e in host.events_after(2)] == list(range(3, 9))
    host.close()
    restored = SessionHost(Session(ScriptedTransport([]), host.session.ctx), lambda e: None)
    assert [e["seq"] for e in restored.events_after(0)] == list(range(1, 9))
    assert restored.publish({"type": "ready"})["seq"] == 9
    restored.close()


def test_ready_precedes_consent_and_eof_is_undecided(tmp_path):
    host, events, arrived = make_host(tmp_path)
    host.attach("tui", "tui")
    assert host.start()
    assert arrived.wait(5)
    assert [e["type"] for e in events[:2]] == ["ready", "permission_request"]
    request = events[1]
    assert request["mode"] == "ask" and request["choices"] == ["approve", "reject"]
    host.close()
    assert host.wait_idle(5)
    assert not host.started
    assert any(
        e["type"] == "gate" and e["choice"] == "undecided" for e in host.session.ctx.log.events()
    )


def test_restart_resolves_a_persisted_unanswered_gate(tmp_path):
    host, _, _ = make_host(tmp_path)
    host.publish(
        {
            "type": "permission_request",
            "request_id": "crashed",
            "gate": "G6",
            "title": "Apply",
            "detail": "",
            "payload": {"diff": "full diff"},
        }
    )
    host.close()
    restored = SessionHost(Session(ScriptedTransport([]), host.session.ctx), lambda event: None)
    assert restored.state()["pending"] is None
    result = restored.events_after(1)
    assert result[-1]["type"] == "gate_result"
    assert result[-1]["choice"] == "undecided"
    restored.close()


def test_audit_failure_cannot_emit_completed_done(tmp_path, monkeypatch):
    host, events, _ = make_host(tmp_path)

    def fail(event):
        raise OSError("disk unavailable")

    monkeypatch.setattr(host.session.ctx.log, "append", fail)
    assert host.submit("hi")
    assert host.wait_idle(5)
    assert not any(e["type"] == "done" and e["reason"] == "completed" for e in events)
    assert host.session.last_outcome == "failed"
    assert any(e["type"] == "error" and "audit" in e["message"] for e in events)
    host.close()
