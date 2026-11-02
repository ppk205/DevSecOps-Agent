"""Tool registry tests: gates, argument validation and untrusted wrapping."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.harness.conftest import call, make_ctx
from vulnscan.decisions.config import LayaConfig
from vulnscan.harness.gates import GateDecision, GateKeeper
from vulnscan.harness.messages import ToolCall
from vulnscan.harness.tools import REGISTRY, ToolContext, run_tool, schemas
from vulnscan.harness.workspace import Candidate, FixProposal, Hop, ProposedFinding


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
    ctx.ws.findings["f1"].path = [Hop("A.java", 1, "code")]
    assert (
        call(ctx, "propose_fix", finding_id="f1", diff=_diff("A.java", 1, ["-a", "+b"]))["status"]
        == "rejected"
    )
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
    diff = "--- a/A.java\n+++ b/A.java\n@@ -10,0 +11,81 @@\n" + "\n".join(body) + "\n"
    error = call(ctx, "propose_fix", finding_id="f1", diff=diff)["error"]
    assert "the limit is 80" in error
    assert "A.java:10" in error
    assert asked == []


def test_fix_near_hop_reaches_g6(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, ["reject"])
    _confirmed_with_hop(ctx)
    result = call(ctx, "propose_fix", finding_id="f1", diff=_diff("A.java", 22, ["-a", "+b"]))
    assert result["status"] == "rejected"
    assert asked == ["G6"]


@pytest.mark.parametrize("start,count", [(21, 20), (1, 25)])
def test_fix_hunk_must_fit_entirely_inside_cited_window(
    tmp_path: Path, start: int, count: int
) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    _confirmed_with_hop(ctx, line=20)
    diff = _diff("A.java", start, ["-old", "+new", *[" context"] * (count - 1)], count)
    result = call(ctx, "propose_fix", finding_id="f1", diff=diff)
    assert "A.java" in result["error"] and "15 lines" in result["error"]
    assert asked == []


@pytest.mark.parametrize(
    "diff", ["x", "--- a/A.java\n+++ b/A.java\n", _diff("A.java", 10, ["-a", "+b"], count=50)]
)
def test_fix_malformed_diff_never_reaches_g6(tmp_path: Path, diff: str) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    _confirmed_with_hop(ctx)
    assert "error" in call(ctx, "propose_fix", finding_id="f1", diff=diff)
    assert asked == [] and ctx.ws.fixes == {}


def test_exported_fix_rescan_is_gated_and_unavailable(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, ["approve"])
    ctx.ws.fixes["Xf1"] = FixProposal(
        "Xf1", "f1", _diff("A.java", 1, ["-a", "+b"]), status="exported"
    )
    assert call(ctx, "rescan", finding_id="f1") == {
        "result": "unavailable: target is not a git repository"
    }
    assert asked == ["G7"]


@pytest.mark.parametrize("edited", ["missing", "../f1", [], "f2"])
def test_rescan_validates_edited_finding_before_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, edited: Any
) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    ctx.ws.fixes["Xf1"] = FixProposal("Xf1", "f1", "", status="applied")
    ctx.ws.fixes["Xf2"] = FixProposal("Xf2", "f2", "", status="deferred")
    ctx.gates = GateKeeper(
        lambda req: GateDecision(req.gate, "edit", edits={"finding_id": edited}), ctx.log.append
    )
    scanned = []
    monkeypatch.setattr(
        "vulnscan.harness.tools.rescan_fix", lambda *args: scanned.append(args) or "candidate gone"
    )
    assert "error" in call(ctx, "rescan", finding_id="f1")
    assert scanned == []


def test_rescan_uses_valid_edited_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    for fid in ("f1", "f2"):
        ctx.ws.fixes["X" + fid] = FixProposal("X" + fid, fid, "", status="applied")
    ctx.gates = GateKeeper(
        lambda req: GateDecision(req.gate, "edit", edits={"finding_id": "f2"}), ctx.log.append
    )
    scanned = []
    monkeypatch.setattr(
        "vulnscan.harness.tools.rescan_fix",
        lambda ws, fix, root: scanned.append(fix.finding_id) or "still present",
    )
    assert call(ctx, "rescan", finding_id="f1") == {"result": "still present"}
    assert scanned == ["f2"]


def test_laya_off_reports_skip_without_backend_and_honors_g2_edits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    ctx.laya_config = LayaConfig(mode="off")
    ctx.laya_agent = None
    for cid in ("c1", "c2"):
        ctx.ws.candidates[cid] = Candidate(cid, "CWE-89", "sql_concat", "A.java", 1, "code")
    requests = []

    def asker(req: Any) -> GateDecision:
        requests.append(req)
        return GateDecision(req.gate, "edit", edits={"candidate_ids": ["c2"]})

    ctx.gates = GateKeeper(asker, ctx.log.append)
    backend_calls = []
    monkeypatch.setattr(
        "vulnscan.harness.triage.LayaDecisionBackend", lambda **kwargs: backend_calls.append(kwargs)
    )
    result = call(ctx, "laya_triage", candidate_ids=["c1"])
    assert result == {
        "routes": {
            "c2": {
                "route": "human_review",
                "confidence": None,
                "status": "skipped",
                "reasons": ["Laya disabled for S1"],
            }
        }
    }
    assert backend_calls == []
    assert "skip" in requests[0].detail.lower()
    assert ctx.ws.candidates["c1"].laya_route is None
    assert ctx.ws.candidates["c2"].laya_route == "human_review"
    assert ctx.ws.findings == {} and ctx.ws.open_batch == set()


def test_laya_invalid_edited_ids_do_not_run_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    ctx.ws.candidates["c1"] = Candidate("c1", "CWE-89", "sql_concat", "A.java", 1, "code")
    ctx.gates = GateKeeper(
        lambda req: GateDecision(req.gate, "edit", edits={"candidate_ids": ["missing"]}),
        ctx.log.append,
    )
    calls = []
    monkeypatch.setattr(
        "vulnscan.harness.tools.triage_candidates", lambda *args: calls.append(args) or {}
    )
    assert "unknown candidate" in call(ctx, "laya_triage", candidate_ids=["c1"])["error"]
    assert calls == []


def test_unsafe_stored_finding_id_never_reaches_fix_gate(tmp_path: Path) -> None:
    ctx, asked = make_ctx(tmp_path, [])
    _confirmed_with_hop(ctx)
    ctx.ws.findings["../f1"] = ctx.ws.findings.pop("f1")
    result = call(ctx, "propose_fix", finding_id="../f1", diff=_diff("A.java", 10, ["-a", "+b"]))
    assert "finding id" in result["error"] and asked == []


def test_rescan_rejects_unsafe_stored_edited_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, _ = make_ctx(tmp_path, [])
    for fid in ("f1", "../f2"):
        ctx.ws.fixes["X" + fid] = FixProposal("X" + fid, fid, "", status="applied")
    ctx.gates = GateKeeper(
        lambda req: GateDecision(req.gate, "edit", edits={"finding_id": "../f2"}), ctx.log.append
    )
    scanned = []
    monkeypatch.setattr(
        "vulnscan.harness.tools.rescan_fix", lambda *args: scanned.append(args) or "candidate gone"
    )
    assert "finding id" in call(ctx, "rescan", finding_id="f1")["error"]
    assert scanned == []
