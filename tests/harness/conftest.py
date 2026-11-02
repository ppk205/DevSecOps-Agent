"""Shared harness test helpers: scripted askers, tool calls and fix fixtures."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.harness.fakes import BatchAgent
from vulnscan.decisions.config import load_config
from vulnscan.harness.audit import SessionLog
from vulnscan.harness.gates import GateDecision, GateKeeper, GateRequest
from vulnscan.harness.messages import ToolCall
from vulnscan.harness.tools import ToolContext, run_tool
from vulnscan.harness.workspace import Candidate, ProposedFinding, Workspace

GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]
DIFF = """--- a/A.java
+++ b/A.java
@@ -1 +1 @@
-class A { int r(){ return new Random().nextInt(); } }
+class A { int r(){ return new java.security.SecureRandom().nextInt(); } }
"""


def scripted(lines: list[str]) -> Any:
    it = iter(lines)
    return lambda prompt="": next(it)


def make_ctx(
    tmp_path: Path, answers: list[str], mode: str = "ask"
) -> tuple[ToolContext, list[str]]:
    (tmp_path / "t").mkdir()
    (tmp_path / "t/A.java").write_text(
        'class A { void a(Statement s, String n){ s.executeQuery("SELECT " + n); } }\n'
    )
    asked: list[str] = []

    def asker(req: GateRequest) -> GateDecision:
        asked.append(req.gate.value)
        return GateDecision(req.gate, answers.pop(0))

    log = SessionLog(tmp_path / "s.jsonl")
    return (
        ToolContext(
            Workspace.open(tmp_path / "t"),
            GateKeeper(asker, log.append, mode=mode),
            log,
            load_config("config/laya.json"),
            BatchAgent(),
            tmp_path / "wt",
        ),
        asked,
    )


def call(ctx: ToolContext, name: str, **args: Any) -> dict[str, Any]:
    return json.loads(run_tool(ctx, ToolCall("1", name, args)))


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "A.java").write_text("class A { int r(){ return new Random().nextInt(); } }\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(GIT + ["add", "."], cwd=repo, check=True)
    subprocess.run(GIT + ["commit", "-qm", "i"], cwd=repo, check=True)
    w = Workspace.open(repo)
    w.candidates["c1"] = Candidate("c1", "CWE-330", "weak_random", "A.java", 1, "")
    w.findings["f1"] = ProposedFinding("f1", "c1", "t", "CWE-330", [], "", "", status="confirmed")
    return w
