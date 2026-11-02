"""Session loop tests: tool rounds, rejections, budget, resume and provider switch."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.harness.conftest import make_ctx
from tests.harness.fakes import ScriptedTransport
from vulnscan.harness.audit import SessionLog
from vulnscan.harness.messages import Message, ProviderError, Reply, ToolCall, Usage
from vulnscan.harness.providers import BUILTIN_PROFILES
from vulnscan.harness.session import Session
from vulnscan.harness.workspace import Candidate, FixProposal, Hop, ProposedFinding
from vulnscan.providers.budget import BudgetManager


def tool(name: str, **args: Any) -> Reply:
    return Reply(
        Message("assistant", "", [ToolCall(name + "-id", name, args)]), Usage(10, 5), "fake"
    )


def text(t: str) -> Reply:
    return Reply(Message("assistant", t), Usage(3, 2), "fake")


def test_three_turn_tool_session_is_logged(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, ["approve", "approve"])
    s = Session(
        ScriptedTransport(
            [
                tool("propose_scan_plan", scope=["**/*.java"], classes=["CWE-89"]),
                tool("inventory", globs=["**/*.java"]),
                text("1 file"),
            ]
        ),
        ctx,
    )
    out = s.send("scan it")
    assert [m.role for m in out] == ["user", "assistant", "tool", "assistant", "tool", "assistant"]
    assert asked == ["G1", "G2"] and ctx.log.totals()["input_tokens"] == 23
    assert [m.content for m in SessionLog(ctx.log.path).messages()][-1] == "1 file"


def test_rejected_call_is_not_repeated_until_new_user_message(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, ["reject", "approve"])
    plan = {"scope": ["**/*.java"], "classes": ["CWE-89"]}
    s = Session(
        ScriptedTransport(
            [
                tool("propose_scan_plan", **plan),
                tool("propose_scan_plan", **plan),
                text("ok"),
                tool("propose_scan_plan", **plan),
                text("done"),
            ]
        ),
        ctx,
    )
    s.send("scan")
    assert asked == ["G1"] and "already rejected" in s.messages[-2].content
    s.send("try again")
    assert asked == ["G1", "G1"]


def test_max_rounds_stops(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    s = Session(ScriptedTransport([tool("grep", pattern="x")] * 5), ctx, max_rounds=3)
    assert s.send("loop")[-1].content == "Stopped after 3 tool rounds."


def test_provider_error_is_saved_and_session_resumes(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    s = Session(ScriptedTransport([ProviderError("HTTP 500")]), ctx)
    assert s.send("hi")[-1].content == "Provider error: HTTP 500"
    assert any(e["type"] == "error" for e in ctx.log.events())
    assert next(m.content for m in Session(ScriptedTransport([]), ctx).messages) == "hi"


def test_budget_exhausted_stops_without_calling_provider(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    t = ScriptedTransport([text("never")])
    out = Session(t, ctx, budget=BudgetManager(total_usd=1.0, reserve_usd=2.0)).send("hi")
    assert t.calls == [] and out[-1].content.startswith("Provider error:")


def test_switch_to_cloud_provider_asks_g0_again(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, ["reject"])
    s = Session(ScriptedTransport([]), ctx)
    cloud = ScriptedTransport([], profile=BUILTIN_PROFILES["deepseek"], model="deepseek-chat")
    assert s.switch(cloud) is False and asked == ["G0"] and s.transport.profile.id == "ollama"
    assert s.switch(
        ScriptedTransport([], profile=BUILTIN_PROFILES["lmstudio"], model="m")
    ) is True and asked == ["G0"]


def test_snapshot_restores_workspace_and_budget_without_running_tools(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    ctx.ws.plan = {"scope": ["A.java"], "classes": ["CWE-89"]}
    ctx.ws.candidates["c"] = Candidate("c", "CWE-89", "sql_concat", "A.java", 1, "x", selected=True)
    ctx.ws.findings["f"] = ProposedFinding(
        "f",
        "c",
        "proposal",
        "CWE-89",
        [Hop("A.java", 1, "x")],
        "",
        "",
        status="confirmed",
        decided_by="tui",
    )
    ctx.ws.fixes["x"] = FixProposal("x", "f", "diff", status="deferred")
    ctx.ws.open_batch = {"c"}
    ctx.log.append(
        {
            "type": "usage",
            "input_tokens": 10,
            "output_tokens": 5,
            "cost_usd": 1.25,
            "provider": "ollama",
        }
    )
    session = Session(ScriptedTransport([]), ctx)
    session.snapshot()
    ctx.ws.candidates.clear()
    ctx.ws.findings.clear()
    ctx.ws.fixes.clear()
    ctx.ws.open_batch.clear()
    transport = ScriptedTransport([])
    restored = Session(transport, ctx, budget=BudgetManager(total_usd=50))
    assert transport.calls == []
    assert restored.ctx.ws.findings["f"].status == "confirmed"
    assert restored.ctx.ws.findings["f"].path == [Hop("A.java", 1, "x")]
    assert restored.ctx.ws.fixes["x"].status == "deferred"
    assert restored.ctx.ws.open_batch == {"c"}
    assert restored.budget.spent == 1.25


def test_snapshot_rejects_foreign_target_before_restoring(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    ctx.log.append(
        {
            "type": "workspace_state",
            "version": 1,
            "target": str(tmp_path / "other"),
            "commit": "unversioned",
        }
    )
    import pytest

    with pytest.raises(ValueError, match="target"):
        Session(ScriptedTransport([]), ctx)
