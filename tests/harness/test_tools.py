"""Tool registry tests: gates, argument validation and untrusted wrapping."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.harness.conftest import call, make_ctx
from vulnscan.harness.messages import ToolCall
from vulnscan.harness.tools import REGISTRY, ToolContext, run_tool, schemas
from vulnscan.harness.workspace import Hop, ProposedFinding


def test_registry_has_no_write_or_shell_tool() -> None:
    names = {s["name"] for s in schemas()}
    assert names == set(REGISTRY)
    assert not names & {"apply_fix", "shell", "exec", "write_file", "run_command"}


def test_unknown_tool_and_bad_args_ask_no_gate(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    assert "unknown tool" in call(ctx, "rm_rf")["error"]
    assert "invalid arguments" in call(ctx, "inventory")["error"]
    assert (
        "invalid arguments"
        in json.loads(run_tool(ctx, ToolCall("1", "grep", {"_unparsed": "{bad"})))["error"]
    )
    assert asked == []


def test_rejected_plan_blocks_scanning(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, ["reject"])
    assert (
        call(ctx, "propose_scan_plan", scope=["**/*.java"], classes=["CWE-89"])["status"]
        == "rejected"
    )
    assert "no approved scan plan" in call(ctx, "inventory", globs=["**/*.java"])["error"]


def test_reads_need_an_approved_batch_and_are_marked_untrusted(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, ["approve", "approve", "approve", "approve", "approve"])
    call(ctx, "propose_scan_plan", scope=["**/*.java"], classes=["CWE-89"])
    assert "no approved investigation batch" in call(ctx, "read_file", path="A.java")["error"]
    cid = call(ctx, "extract_candidates")["candidates"][0]["id"]
    call(ctx, "laya_triage")
    call(ctx, "select_candidates", candidate_ids=[cid], reason="sql")
    call(ctx, "begin_investigation", candidate_ids=[cid])
    out = call(ctx, "read_file", path="A.java")["content"]
    assert out.startswith('<untrusted_code path="A.java">') and "executeQuery" in out
    assert "error" in call(ctx, "read_file", path="../s.jsonl")


def test_auto_mode_leaves_finding_proposed(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, [], mode="auto")
    call(ctx, "propose_scan_plan", scope=["**/*.java"], classes=["CWE-89"])
    cid = call(ctx, "extract_candidates")["candidates"][0]["id"]
    call(ctx, "laya_triage")
    call(ctx, "select_candidates", candidate_ids=[cid], reason="r")
    call(ctx, "begin_investigation", candidate_ids=[cid])
    r = call(
        ctx,
        "propose_finding",
        candidate_id=cid,
        title="SQLi",
        cwe="CWE-89",
        path=[
            {
                "file": "A.java",
                "line": 1,
                "code": 'executeQuery("SELECT " + n)',
                "note": "sink",
            }
        ],
        explanation="n concatenated",
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    )
    f = ctx.ws.findings[r["finding_id"]]
    assert f.status == "proposed" and f.cvss_score == 9.3 and f.evidence_errors == []
    assert asked == []


def test_fix_needs_confirmed_finding_and_human_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, asked = make_ctx(tmp_path, ["reject"], mode="auto")
    applied: list[Any] = []
    monkeypatch.setattr(
        "vulnscan.harness.tools.apply_fix", lambda ws, fix, root: applied.append(fix) or "b"
    )
    ctx.ws.findings["f1"] = ProposedFinding("f1", "c", "t", "CWE-89", [], "", "", status="proposed")
    assert "not confirmed" in call(ctx, "propose_fix", finding_id="f1", diff="x")["error"]
    ctx.ws.findings["f1"].status = "confirmed"
    assert call(ctx, "propose_fix", finding_id="f1", diff="x")["status"] == "rejected"
    assert asked == ["G6"] and applied == []


def _confirmed_with_hop(ctx: ToolContext, file: str = "A.java", line: int = 10) -> None:
    ctx.ws.findings["f1"] = ProposedFinding(
        "f1", "c", "t", "CWE-89", [Hop(file, line, "code")], "", "", status="confirmed"
    )


def _diff(file: str, start: int, body: list[str], count: int = 1) -> str:
    header = f"@@ -{start},{count} +{start},{count} @@"
    return "\n".join([f"--- a/{file}", f"+++ b/{file}", header, *body]) + "\n"


def test_fix_outside_cited_code_is_refused(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    _confirmed_with_hop(ctx)
    error = call(ctx, "propose_fix", finding_id="f1", diff=_diff("Other.java", 10, ["-a", "+b"]))[
        "error"
    ]
    assert "Other.java" in error and "not cited" in error
    assert asked == []


def test_fix_far_from_hop_is_refused(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    _confirmed_with_hop(ctx)
    error = call(ctx, "propose_fix", finding_id="f1", diff=_diff("A.java", 50, ["-a", "+b"]))[
        "error"
    ]
    assert "more than 15 lines" in error
    assert asked == []


def test_large_fix_is_refused(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    _confirmed_with_hop(ctx)
    body = [f"+line {index}" for index in range(81)]
    error = call(ctx, "propose_fix", finding_id="f1", diff=_diff("A.java", 10, body, count=81))[
        "error"
    ]
    assert "the limit is 80" in error
    assert asked == []


def test_fix_near_hop_reaches_g6(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, ["reject"])
    _confirmed_with_hop(ctx)
    result = call(ctx, "propose_fix", finding_id="f1", diff=_diff("A.java", 22, ["-a", "+b"]))
    assert result["status"] == "rejected"
    assert asked == ["G6"]
