"""Report tests: finding cards, decision log and JSON export."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.harness.audit import SessionLog
from vulnscan.harness.report import export, render_markdown
from vulnscan.harness.workspace import (
    Candidate,
    FixProposal,
    Hop,
    ProposedFinding,
    Workspace,
)


def test_report_cards_pending_and_log(tmp_path: Path) -> None:
    ws = Workspace.open(tmp_path)
    ws.candidates["c"] = Candidate(
        "c",
        "CWE-89",
        "sql_concat",
        "A.java",
        4,
        "",
        laya_route="cross_file_analysis",
        laya_confidence=0.71,
    )
    ws.findings["f1"] = ProposedFinding(
        "f1",
        "c",
        "SQL injection in search",
        "CWE-89",
        [
            Hop("A.java", 2, 'req.getParameter("n")', "source"),
            Hop("A.java", 4, "executeQuery(sql + n)", "sink"),
        ],
        "n reaches the query",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        9.3,
        tokens=1200,
    )
    ws.fixes["x"] = FixProposal("x", "f1", "--- a/A.java\n+++ b/A.java\n", status="deferred")
    log = SessionLog(tmp_path / "s.jsonl")
    log.append(
        {
            "type": "gate",
            "gate": "G5",
            "choice": "undecided",
            "person": "auto",
            "mode": "auto",
            "reason": "auto mode: awaiting human /review",
        }
    )
    md = render_markdown(ws, log)
    for needle in [
        "## Awaiting human review",
        "f1",
        "A.java:2",
        'req.getParameter("n")',
        "cross_file_analysis",
        "9.3",
        "all citations verified",
        "```diff",
        "deferred",
        "1200",
        "## Decision log",
        "| G5 | undecided | auto |",
    ]:
        assert needle in md
    paths = export(ws, log, tmp_path / "out")
    assert json.loads(paths["json"].read_text())["findings"][0]["id"] == "f1"
