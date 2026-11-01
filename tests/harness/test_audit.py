"""Session log tests: resume, clear, totals and a truncated last line."""

from __future__ import annotations

from pathlib import Path

from vulnscan.harness.audit import SessionLog, new_session_path
from vulnscan.harness.messages import Message, ToolCall


def test_messages_survive_a_restart(tmp_path: Path) -> None:
    p = tmp_path / "s.jsonl"
    log = SessionLog(p)
    log.append({"type": "message", "message": Message("user", "hi").to_dict()})
    log.append(
        {
            "type": "message",
            "message": Message(
                "assistant", "", [ToolCall("1", "grep", {"pattern": "x"})]
            ).to_dict(),
        }
    )
    msgs = SessionLog(p).messages()
    assert [m.role for m in msgs] == ["user", "assistant"] and msgs[1].tool_calls[0].arguments == {
        "pattern": "x"
    }


def test_clear_drops_earlier_messages(tmp_path: Path) -> None:
    log = SessionLog(tmp_path / "s.jsonl")
    log.append({"type": "message", "message": Message("user", "old").to_dict()})
    log.append({"type": "clear"})
    log.append({"type": "message", "message": Message("user", "new").to_dict()})
    assert [m.content for m in log.messages()] == ["new"]


def test_totals_sum_usage(tmp_path: Path) -> None:
    log = SessionLog(tmp_path / "s.jsonl")
    log.append({"type": "usage", "input_tokens": 10, "output_tokens": 2, "cost_usd": 0.5})
    log.append({"type": "usage", "input_tokens": 5, "output_tokens": 1, "cost_usd": 0.25})
    assert log.totals() == {"input_tokens": 15, "output_tokens": 3, "cost_usd": 0.75, "turns": 2}


def test_truncated_last_line_is_ignored(tmp_path: Path) -> None:
    p = tmp_path / "s.jsonl"
    SessionLog(p).append({"type": "mode", "mode": "auto"})
    with p.open("a", encoding="utf-8") as f:
        f.write('{"type": "mes')
    assert [e["type"] for e in SessionLog(p).events()] == ["mode"]


def test_new_session_path_is_unique(tmp_path: Path) -> None:
    assert new_session_path(tmp_path) != new_session_path(tmp_path)
