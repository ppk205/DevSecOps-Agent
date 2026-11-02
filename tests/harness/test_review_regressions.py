"""Review regressions: FR-16, QR-01/04/12/20 and harness safety rules."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.harness.fakes import ScriptedTransport
from tests.harness.test_console import scripted
from tests.harness.test_fixes import DIFF
from tests.harness.test_tools import call, make_ctx
from vulnscan.harness.audit import SessionLog
from vulnscan.harness.console import ChatConsole, console_asker
from vulnscan.harness.fixes import apply_fix, rescan_fix
from vulnscan.harness.gates import Gate, GateDecision, GateKeeper, GateRequest
from vulnscan.harness.messages import Message, ToolCall
from vulnscan.harness.providers import (
    BUILTIN_PROFILES,
    AnthropicTransport,
    ChatCompletionsTransport,
)
from vulnscan.harness.report import export, render_markdown
from vulnscan.harness.scanning import extract_candidates, inventory, lookup_route
from vulnscan.harness.session import Session
from vulnscan.harness.workspace import FixProposal, Hop, PathEscape, ProposedFinding, Workspace

pytest_plugins = ["tests.harness.test_fixes"]


@pytest.mark.parametrize("operation", ["grep", "inventory", "extract", "route"])
@pytest.mark.parametrize("link_kind", ["file", "directory"])
def test_enumerated_links_never_read_outside_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, link_kind: str
) -> None:
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    source = outside / "Outside.java"
    source.write_text("class Outside { Random r = new Random(); }", encoding="utf-8")
    link = target / ("linked" if link_kind == "directory" else "Outside.java")
    try:
        link.symlink_to(
            outside if link_kind == "directory" else source,
            target_is_directory=link_kind == "directory",
        )
    except OSError:
        if os.name != "nt" or link_kind != "directory":
            pytest.skip("file symlinks require OS permission")
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)], check=True, capture_output=True
        )
    original_open = Path.open

    def guarded_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        assert not path.resolve().is_relative_to(outside), "outside-target read"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    workspace = Workspace(target, "unversioned")
    globs = ["linked/*.java"] if link_kind == "directory" else ["**/*"]
    if operation == "grep":
        assert workspace.grep("Random", globs[0]) == []
    elif operation == "inventory":
        assert inventory(workspace, globs) == []
    elif operation == "extract":
        assert extract_candidates(workspace, paths=globs) == []
    else:
        assert lookup_route(workspace, "Outside")["servlets"] == []


@pytest.mark.parametrize("name", [".env", ".env.production", ".secrets", "nested/.env.local"])
def test_credential_files_are_blocked_before_open(tmp_path: Path, name: str) -> None:
    workspace = Workspace(tmp_path, "unversioned")
    # No credential fixture is needed: exclusion must precede opening the path.
    with pytest.raises(PathEscape, match="excluded"):
        workspace.read(name)


def test_enumeration_excludes_credentials_and_preserves_example(tmp_path: Path) -> None:
    for name in [".env", ".env.production", ".secrets", ".env.example"]:
        (tmp_path / name).write_text("fixture-only", encoding="utf-8")
    workspace = Workspace(tmp_path, "unversioned")
    assert [item["path"] for item in inventory(workspace, ["**/*"])] == [".env.example"]
    assert workspace.grep("fixture") == [(".env.example", 1, "fixture-only")]
    assert "fixture-only" in workspace.read(".env.example")


@pytest.mark.parametrize("bad", ["src/../A.java", "C:relative.java"])
def test_resolve_rejects_parent_components_and_drive_paths(tmp_path: Path, bad: str) -> None:
    with pytest.raises(PathEscape):
        Workspace(tmp_path, "unversioned").resolve(bad)


@pytest.mark.parametrize("protocol", ["chat", "anthropic"])
def test_provider_redacts_normal_request_and_response(protocol: str) -> None:
    sentinel = "sk-" + "syntheticfixture123456"
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content.decode())
        body = (
            {"choices": [{"message": {"content": sentinel}}]}
            if protocol == "chat"
            else {"content": [{"type": "text", "text": sentinel}]}
        )
        return httpx.Response(200, json=body)

    profile = BUILTIN_PROFILES["ollama"].model_copy(update={"api_key_env": ""})
    transport_cls = ChatCompletionsTransport if protocol == "chat" else AnthropicTransport
    transport = transport_cls(
        profile, "fixture", http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    messages = [
        Message("user", sentinel),
        Message("assistant", "", [ToolCall("c", "grep", {"pattern": sentinel})]),
        Message("tool", sentinel, tool_call_id="c"),
    ]
    reply = transport.complete(sentinel, messages, [])
    assert sentinel not in seen[0] and "[REDACTED]" in seen[0]
    assert sentinel not in reply.message.content
    assert messages[0].content == sentinel  # boundary must not mutate tool inputs


def test_logs_reports_and_display_redact_normal_content(tmp_path: Path) -> None:
    sentinel = "sk-ant-" + "syntheticfixture123456"
    ctx, _ = make_ctx(tmp_path, [])
    ctx.log.append({"type": "message", "message": Message("tool", sentinel).to_dict()})
    ctx.log.append({"type": "gate", "payload": {"nested": [sentinel]}, "reason": sentinel})
    ctx.ws.findings["f"] = ProposedFinding(
        "f", "c", sentinel, "CWE-798", [Hop("A.java", 1, sentinel)], sentinel, ""
    )
    ctx.ws.fixes["x"] = FixProposal("x", "f", sentinel)
    assert sentinel not in ctx.log.path.read_text(encoding="utf-8")
    assert sentinel not in render_markdown(ctx.ws, ctx.log)
    for path in export(ctx.ws, ctx.log, tmp_path / "reports").values():
        assert sentinel not in path.read_text(encoding="utf-8")
    output: list[str] = []
    console = ChatConsole(Session(ScriptedTransport([]), ctx), write=output.append)
    console._print(Message("tool", sentinel))
    console._print(Message("assistant", sentinel, [ToolCall("c", "grep", {"pattern": sentinel})]))
    assert sentinel not in "\n".join(output)


def test_full_diff_is_displayed_before_g6_answer() -> None:
    diff = "--- a/A.java\n+++ b/A.java\n" + " context\n" * 500 + "+final-line\n"
    output: list[str] = []

    def answer(prompt: str) -> str:
        assert diff in "\n".join(output)
        return "a"

    decision = console_asker(answer, output.append)(
        GateRequest(Gate.G6_FIX, "fix", "detail", {"diff": diff})
    )
    assert decision.choice == "apply"


@pytest.mark.parametrize("edited", ["{bad", "[]", "null", "", '"text"'])
def test_malformed_gate_edits_never_approve(tmp_path: Path, edited: str) -> None:
    log = SessionLog(tmp_path / "gate.jsonl")
    keeper = GateKeeper(console_asker(scripted(["e", edited]), lambda _: None), log.append)
    decision = keeper.ask(GateRequest(Gate.G2_SCAN, "scan", "detail"))
    assert not decision.approved and decision.choice == "undecided"
    assert log.events()[-1]["choice"] == "undecided"


def test_investigation_requires_triage(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, [], mode="auto")
    call(ctx, "propose_scan_plan", scope=["**/*.java"], classes=["CWE-89"])
    cid = call(ctx, "extract_candidates")["candidates"][0]["id"]
    call(ctx, "select_candidates", candidate_ids=[cid], reason="test")
    result = call(ctx, "begin_investigation", candidate_ids=[cid])
    assert "triage" in result.get("error", "").lower() and not ctx.ws.open_batch
    assert "error" in call(ctx, "read_file", path="A.java")
    call(ctx, "laya_triage", candidate_ids=[cid])
    assert call(ctx, "begin_investigation", candidate_ids=[cid])["status"] == "approved"


def test_edited_batch_cannot_add_untriaged_candidates(tmp_path: Path) -> None:
    ctx, _ = make_ctx(tmp_path, [], mode="auto")
    call(ctx, "propose_scan_plan", scope=["**/*.java"], classes=["CWE-89"])
    cid = call(ctx, "extract_candidates")["candidates"][0]["id"]
    call(ctx, "laya_triage", candidate_ids=[cid])
    from dataclasses import replace

    ctx.ws.candidates["untriaged"] = replace(
        ctx.ws.candidates[cid], id="untriaged", laya_route=None
    )
    call(ctx, "select_candidates", candidate_ids=[cid, "untriaged"], reason="test")
    ctx.gates = GateKeeper(
        lambda req: GateDecision(req.gate, "edit", edits={"candidate_ids": ["untriaged"]}),
        ctx.log.append,
    )
    assert "triage" in call(ctx, "begin_investigation", candidate_ids=[cid])["error"].lower()
    assert not ctx.ws.open_batch


def test_relative_worktree_uses_callers_directory(
    ws: Workspace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    fix = FixProposal("x", "f1", DIFF)
    apply_fix(ws, fix)
    assert (tmp_path / ".devsec/worktrees/f1/A.java").is_file()
    assert rescan_fix(ws, fix) == "candidate gone"


def test_unrelated_diff_does_not_remove_original_candidate(ws: Workspace, tmp_path: Path) -> None:
    diff = "--- /dev/null\n+++ b/Other.java\n@@ -0,0 +1 @@\n+class Other {}\n"
    fix = FixProposal("x", "f1", diff)
    apply_fix(ws, fix, tmp_path / "worktrees")
    assert rescan_fix(ws, fix, tmp_path / "worktrees") == "still present"


@pytest.mark.parametrize("query", ["Users", "/admin/users"])
@pytest.mark.parametrize("pattern", ["/admin/*", "/*", "/admin/users"])
def test_fr16_lookup_includes_applicable_filter_guards(
    tmp_path: Path, query: str, pattern: str
) -> None:
    (tmp_path / "Users.java").write_text(
        '@WebServlet("/admin/users")\nclass Users {}', encoding="utf-8"
    )
    (tmp_path / "Guard.java").write_text(
        f'@WebFilter("{pattern}")\nclass Guard {{ void check() {{ requireAdmin(); }} }}',
        encoding="utf-8",
    )
    result = lookup_route(Workspace(tmp_path, "unversioned"), query)
    assert result["filters"] == [{"class": "Guard", "url_pattern": pattern}]
    assert result["auth_check"] is True


@pytest.mark.parametrize("pattern", ["/administrator/*", "/admin/other", "/", "*.jsp"])
def test_fr16_unrelated_filter_cannot_guard_route(tmp_path: Path, pattern: str) -> None:
    (tmp_path / "Users.java").write_text(
        '@WebServlet("/admin/users")\nclass Users {}', encoding="utf-8"
    )
    (tmp_path / "Guard.java").write_text(
        f'@WebFilter("{pattern}")\nclass Guard {{ void check() {{ requireAdmin(); }} }}',
        encoding="utf-8",
    )
    result = lookup_route(Workspace(tmp_path, "unversioned"), "/admin/users")
    assert result["filters"] == [] and result["auth_check"] is False


def test_fr16_extension_mapping_includes_filter_guard(tmp_path: Path) -> None:
    (tmp_path / "Users.java").write_text('@WebServlet("*.do")\nclass Users {}', encoding="utf-8")
    (tmp_path / "Guard.java").write_text(
        '@WebFilter("*.do")\nclass Guard { void check() { requireAdmin(); } }', encoding="utf-8"
    )
    for query in ["Users", "/admin/users.do"]:
        result = lookup_route(Workspace(tmp_path, "unversioned"), query)
        assert result["servlets"] and result["filters"] and result["auth_check"] is True


def test_fr16_default_servlet_guard_cannot_guard_a_more_specific_route(tmp_path: Path) -> None:
    (tmp_path / "Users.java").write_text(
        '@WebServlet("/admin/users")\nclass Users {}', encoding="utf-8"
    )
    (tmp_path / "Default.java").write_text(
        '@WebServlet("/")\nclass Default { void check() { requireAdmin(); } }',
        encoding="utf-8",
    )
    result = lookup_route(Workspace(tmp_path, "unversioned"), "/admin/users")
    assert result["servlets"] == [
        {"class": "Users", "url_pattern": "/admin/users", "file": "Users.java"}
    ]
    assert result["auth_check"] is False


@pytest.mark.parametrize(
    "lock", ["requirements.lock", "requirements-build.lock", "requirements-scanners.lock"]
)
def test_shipped_exports_include_required_cvss(lock: str) -> None:
    root = Path(__file__).resolve().parents[2]
    assert "cvss==3.6" in (root / lock).read_text(encoding="utf-8")
