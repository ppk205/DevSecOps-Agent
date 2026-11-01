"""Console tests: gate key prompts, slash commands and the CLI refusal."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from tests.harness.fakes import ScriptedTransport
from tests.harness.test_tools import make_ctx
from vulnscan.cli.main import app
from vulnscan.harness.console import ChatConsole, console_asker
from vulnscan.harness.gates import Gate, GateRequest
from vulnscan.harness.session import Session
from vulnscan.harness.workspace import ProposedFinding


def scripted(lines: list[str]) -> Any:
    it = iter(lines)
    return lambda prompt="": next(it)


def test_asker_keys_and_empty_line_is_not_yes() -> None:
    out: list[str] = []
    d = console_asker(scripted(["", "x", "n", "too broad"]), out.append)(
        GateRequest(Gate.G1_PLAN, "plan", "d")
    )
    assert (d.choice, d.reason) == ("reject", "too broad")
    assert console_asker(scripted(["e", '{"scope": ["src/**"]}']), out.append)(
        GateRequest(Gate.G2_SCAN, "s", "d")
    ).edits == {"scope": ["src/**"]}
    assert (
        console_asker(scripted(["a"]), out.append)(GateRequest(Gate.G6_FIX, "f", "d")).choice
        == "apply"
    )


def test_mode_cost_and_review(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, [], mode="ask")
    ctx.ws.findings["f1"] = ProposedFinding("f1", "c", "t", "CWE-89", [], "", "")
    out: list[str] = []
    con = ChatConsole(Session(ScriptedTransport([]), ctx), read=scripted(["c"]), write=out.append)
    con.handle("/mode auto")
    assert ctx.gates.mode == "auto"
    assert any(e.get("mode") == "auto" and e["type"] == "mode" for e in ctx.log.events())
    con.handle("/cost")
    assert "input_tokens" in "\n".join(out)
    con.handle("/review")
    assert ctx.ws.findings["f1"].status == "confirmed"
    assert con.handle("/quit") is False


def test_cli_chat_refuses_without_a_human(tmp_path: Path) -> None:
    r = CliRunner().invoke(
        app,
        [
            "chat",
            "--target",
            str(tmp_path),
            "--provider",
            "ollama",
            "--model",
            "m",
            "--sessions-dir",
            str(tmp_path / "sessions"),
            "-p",
            "hi",
        ],
    )
    assert r.exit_code == 2 and "G0 needs a human" in r.output
