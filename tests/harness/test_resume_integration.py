"""Consent and persisted state stay coherent across console session changes."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from tests.harness.conftest import make_ctx, scripted
from tests.harness.fakes import ScriptedTransport
from tests.harness.test_session import text, tool
from vulnscan.harness.audit import SessionLog
from vulnscan.harness.console import ChatConsole
from vulnscan.harness.messages import Message
from vulnscan.harness.providers import BUILTIN_PROFILES
from vulnscan.harness.session import Session
from vulnscan.harness.workspace import Candidate, FixProposal, Hop, ProposedFinding, Workspace
from vulnscan.providers.budget import BudgetManager


@pytest.mark.parametrize("source", ["ollama", "deepseek"])
@pytest.mark.parametrize("answer", ["approve", "reject", "undecided"])
def test_same_alias_changed_cloud_endpoint_needs_fresh_consent(
    tmp_path: Path, source: str, answer: str
) -> None:
    ctx, asked = make_ctx(tmp_path, [answer], mode="auto")
    ctx.gates.interactive = True
    old = ScriptedTransport([], profile=BUILTIN_PROFILES[source])
    session = Session(old, ctx)
    changed = ScriptedTransport(
        [],
        profile=old.profile.model_copy(update={"base_url": "https://new.example/v1"}),
        model="replacement",
    )
    assert session.switch(changed) is (answer == "approve")
    assert asked == ["G0"]
    assert session.transport is (changed if answer == "approve" else old)
    events = ctx.log.events()
    assert events[0]["gate"] == "G0"
    assert events[0]["payload"]["code_leaves_machine"] is True
    models = [event for event in events if event["type"] == "model"]
    assert len(models) == (1 if answer == "approve" else 0)
    if models:
        assert models[0]["model"] == changed.model


def test_same_cloud_provider_endpoint_model_change_needs_no_new_consent(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    old = ScriptedTransport([], profile=BUILTIN_PROFILES["deepseek"])
    session = Session(old, ctx)
    changed = ScriptedTransport([], profile=old.profile, model="another-model")
    assert session.switch(changed)
    assert session.transport is changed
    assert asked == []
    assert ctx.log.events()[-1]["model"] == "another-model"


def test_rejected_provider_switch_does_not_log_attempt_as_current_model(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, ["reject"])
    old = ScriptedTransport([])
    session = Session(old, ctx)
    assert not session.switch(ScriptedTransport([], profile=BUILTIN_PROFILES["deepseek"]))
    assert session.transport is old
    assert not any(event["type"] == "model" for event in ctx.log.events())
    assert ctx.log.events()[-1]["choice"] == "reject"


def saved_session(session: Session, path: Path) -> Session:
    ctx = replace(session.ctx, log=SessionLog(path), ws=Workspace.open(session.ctx.ws.target))
    saved = Session(ScriptedTransport([]), ctx)
    ctx.ws.plan = {"scope": ["A.java"], "classes": ["CWE-89"]}
    ctx.ws.candidates["c"] = Candidate("c", "CWE-89", "sql_concat", "A.java", 1, "x", selected=True)
    ctx.ws.findings["f"] = ProposedFinding(
        "f", "c", "proposal", "CWE-89", [Hop("A.java", 1, "x")], "", ""
    )
    ctx.ws.fixes["x"] = FixProposal("x", "f", "diff", status="deferred")
    ctx.ws.open_batch = {"c"}
    ctx.ws.batch_tokens = 8
    ctx.log.append({"type": "message", "message": Message("user", "saved history").to_dict()})
    ctx.log.append({"type": "tool_call", "name": "propose_fix", "arguments": {}})
    ctx.log.append(
        {
            "type": "usage",
            "provider": "ollama",
            "input_tokens": 5,
            "output_tokens": 3,
            "cost_usd": 3.25,
        }
    )
    saved.snapshot()
    return saved


def test_console_resume_restores_log_workspace_totals_and_budget_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, asked = make_ctx(tmp_path, ["approve", "approve", "approve"])
    transport = ScriptedTransport(
        [tool("propose_scan_plan", scope=["A.java"], classes=["CWE-89"]), text("continued")]
    )
    old = Session(transport, ctx, max_rounds=7, budget=BudgetManager(20, 2))
    saved = saved_session(old, tmp_path / "saved review.jsonl")
    old.send("old history")
    old_events = ctx.log.events()
    asked.clear()
    transport.calls.clear()
    transport.replies = [tool("propose_scan_plan", scope=["A.java"], classes=[]), text("done")]

    # A resume must not execute the tool-call events stored in the old log.
    def replay_forbidden(*args: object) -> str:
        raise AssertionError("historical tools must not be replayed")

    with monkeypatch.context() as patch:
        patch.setattr("vulnscan.harness.session.run_tool", replay_forbidden)
        console = ChatConsole(old, write=lambda _: None)
        console.handle(f"/resume {saved.ctx.log.path}")

    restored = console.session
    assert restored.ctx.log.path == saved.ctx.log.path
    assert asked == ["G0"]
    assert transport.calls == []
    assert [m.content for m in restored.messages] == ["saved history"]
    assert restored.ctx.ws == saved.ctx.ws
    assert restored.ctx.worktrees == old.ctx.worktrees
    assert restored.max_rounds == 7
    assert restored.budget is not None
    assert restored.budget.spent == 3.25
    assert restored.budget.total_budget == 20
    assert restored.budget._reserve == 2
    assert restored.ctx.log.totals() == saved.ctx.log.totals()
    assert ctx.log.events() == old_events
    # Both subsequent tools and their gates must append to the restored log.
    console.handle("continue")
    assert asked == ["G0", "G1"]
    assert ctx.log.events() == old_events
    assert restored.ctx.log.messages()[-1].content == "done"


def test_console_resume_restored_spend_blocks_provider(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, ["approve"])
    transport = ScriptedTransport([])
    old = Session(transport, ctx, budget=BudgetManager(5, 2))
    saved = saved_session(old, tmp_path / "saved.jsonl")
    output: list[str] = []
    console = ChatConsole(old, write=output.append)
    console.handle(f"/resume {saved.ctx.log.path}")
    console.handle("continue")
    assert asked == ["G0"]
    assert transport.calls == []
    assert "budget exhausted" in "\n".join(output)


@pytest.mark.parametrize("answer", ["reject", "undecided"])
def test_console_resume_refusal_keeps_live_session_intact(tmp_path: Path, answer: str) -> None:
    ctx, asked = make_ctx(tmp_path, [answer])
    old = Session(ScriptedTransport([]), ctx, budget=BudgetManager(20, 2))
    saved = saved_session(old, tmp_path / "saved.jsonl")
    old.messages = [Message("user", "live history")]
    console = ChatConsole(old, write=lambda _: None)
    console.handle(f"/resume {saved.ctx.log.path}")
    assert asked == ["G0"]
    assert console.session is old
    assert old.messages == [Message("user", "live history")]
    assert old.ctx.ws.findings == {}
    assert old.budget.spent == 0
    assert ctx.log.events() == []
    assert saved.ctx.log.events()[-1]["approved"] is False


@pytest.mark.parametrize("invalid", ["missing", "foreign", "commit"])
def test_console_resume_invalid_log_keeps_live_session(tmp_path: Path, invalid: str) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    old = Session(ScriptedTransport([]), ctx)
    path = tmp_path / "saved.jsonl"
    if invalid != "missing":
        saved = saved_session(old, path)
        if invalid == "foreign":
            saved.ctx.ws.target = tmp_path / "other"
        else:
            saved.ctx.ws.commit = "other-commit"
        saved.snapshot()
    output: list[str] = []
    console = ChatConsole(old, write=output.append)
    console.handle(f"/resume {path}")
    assert console.session is old
    assert asked == []
    assert "Cannot resume" in "\n".join(output)
    assert ctx.log.events() == []


@pytest.mark.parametrize(
    ("answers", "status", "reason"),
    [
        (["c"], "confirmed", ""),
        (["r", "not reachable"], "rejected", "not reachable"),
        (["m", "need caller"], "need_more", "need caller"),
        ([], "proposed", ""),
    ],
)
def test_console_review_persists_only_human_decisions_across_restart(
    tmp_path: Path, answers: list[str], status: str, reason: str
) -> None:
    ctx, _ = make_ctx(tmp_path, [], mode="auto")
    session = saved_session(Session(ScriptedTransport([]), ctx), tmp_path / "saved.jsonl")
    console = ChatConsole(session, read=scripted(answers), write=lambda _: None)
    console.handle("/review")
    fresh_ctx = replace(session.ctx, ws=Workspace.open(session.ctx.ws.target))
    restored = Session(ScriptedTransport([]), fresh_ctx)
    finding = restored.ctx.ws.findings["f"]
    assert finding.status == status
    assert finding.reason == reason
    assert finding.decided_by == ("human" if status != "proposed" else "")
    gates = [e for e in fresh_ctx.log.events() if e["type"] == "gate"]
    assert len(gates) == 1
    assert gates[0]["gate"] == "G5" and gates[0]["person"] == "human"
    assert gates[0]["mode"] == "ask"
    assert fresh_ctx.gates.mode == "auto"
