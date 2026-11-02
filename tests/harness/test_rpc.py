"""The stdio protocol uses whole replies and never reads terminal prompts."""

import io
import json
import os
import queue
import subprocess
import sys

import pytest

from vulnscan.harness.gates import Gate, GateRequest
from vulnscan.harness.host import PROTOCOL, bridge_asker
from vulnscan.harness.rpc import RPCController, serve


@pytest.mark.parametrize(
    "reply", [{"choice": "yes_all"}, {"choice": "approve", "edits": []}, {"choice": ""}, None]
)
def test_bridge_asker_invalid_or_closed_is_undecided(reply):
    replies = queue.Queue()

    def emit(event):
        replies.put(None if reply is None else {**reply, "request_id": event["request_id"]})

    decision = bridge_asker(emit, replies)(GateRequest(Gate.G0_SESSION, "start", ""))
    assert decision.choice == "undecided" and not decision.approved


def test_bridge_asker_matches_request_id():
    replies = queue.Queue()

    def emit(event):
        replies.put({"request_id": "old", "choice": "reject"})
        replies.put({"request_id": event["request_id"], "choice": "approve"})

    assert bridge_asker(emit, replies)(GateRequest(Gate.G0_SESSION, "start", "")).approved


def test_malformed_lines_get_errors_not_tracebacks():
    output = io.StringIO()
    assert serve(io.StringIO('[]\n{broken\n{"type":"hello"}\n'), output) == 0
    events = [json.loads(line) for line in output.getvalue().splitlines()]
    assert len(events) == 3 and all(e["type"] == "error" for e in events)
    assert all(e["protocol"] == PROTOCOL for e in events)


def process(tmp_path):
    (tmp_path / "target").mkdir()
    script = tmp_path / "replies.json"
    script.write_text(
        json.dumps(
            [
                {
                    "message": {"role": "assistant", "content": "whole answer"},
                    "usage": {"input_tokens": 2, "output_tokens": 3},
                    "model": "fake",
                }
            ]
        )
    )
    env = {**os.environ, "DEVSEC_CHAT_FAKE_TRANSPORT": str(script)}
    return subprocess.Popen(
        [sys.executable, "-m", "vulnscan.harness.rpc"],
        cwd=tmp_path,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )


def send(proc, **message):
    proc.stdin.write(json.dumps({"protocol": PROTOCOL, **message}) + "\n")
    proc.stdin.flush()


def read_until(proc, kind):
    events = []
    for _ in range(30):
        line = proc.stdout.readline()
        assert line, "host stopped before expected event"
        events.append(json.loads(line))
        assert events[-1]["type"] != "error", events[-1]
        if events[-1]["type"] == kind:
            return events
    raise AssertionError("too many events")


def test_serve_round_trip_over_pipes(tmp_path):
    proc = process(tmp_path)
    try:
        send(proc, type="hello")
        assert read_until(proc, "models")[-1]["items"] == []
        send(
            proc,
            type="start",
            target=str(tmp_path / "target"),
            provider="ollama",
            model="fake",
            mode="ask",
        )
        initial = read_until(proc, "permission_request")
        assert initial[0]["type"] == "ready"
        assert initial[-1]["gate"] == "G0"
        send(proc, type="permission_reply", request_id=initial[-1]["request_id"], choice="approve")
        read_until(proc, "done")
        send(proc, type="user_message", text="hello")
        events = read_until(proc, "done")
        assert [
            e["text"] for e in events if e["type"] == "text_delta" and e.get("role") != "user"
        ] == ["whole answer"]
        proc.stdin.close()
        assert proc.wait(10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_stdin_eof_leaves_pending_gate_undecided(tmp_path):
    proc = process(tmp_path)
    try:
        send(
            proc,
            type="start",
            target=str(tmp_path / "target"),
            provider="ollama",
            model="fake",
            mode="ask",
        )
        read_until(proc, "permission_request")
        proc.stdin.close()
        assert proc.wait(10) == 0
        records = [
            json.loads(line)
            for path in (tmp_path / ".devsec/sessions").glob("*.jsonl")
            for line in path.read_text().splitlines()
        ]
        assert any(r["type"] == "gate" and r["choice"] == "undecided" for r in records)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_model_add_uses_model_protocol_and_never_echoes_key(monkeypatch):
    calls, events = [], []
    monkeypatch.setattr("vulnscan.harness.models.add_model", lambda *args: calls.append(args))
    monkeypatch.setattr("vulnscan.harness.models.list_models", list)
    controller = RPCController(events.append)
    result = controller.handle(
        {
            "protocol": PROTOCOL,
            "type": "model_add",
            "alias": "test",
            "template": None,
            "model_protocol": "openai_compatible",
            "base_url": "http://127.0.0.1:1234/v1",
            "models": ["fake"],
            "key": "fixture-key",
        }
    )
    assert result["ok"]
    assert calls[0][2] == "openai_compatible"
    assert "fixture-key" not in str(events)
    assert events[-1]["type"] == "models"
