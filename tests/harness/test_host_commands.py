"""Command relay, explicit mode consent and snapshot-backed resume."""

from tests.harness.test_host_clients import make_host
from vulnscan.harness.audit import SessionLog
from vulnscan.harness.host import PROTOCOL
from vulnscan.harness.rpc import RPCController
from vulnscan.harness.workspace import Candidate, FixProposal, ProposedFinding


def test_auto_mode_needs_explicit_confirmation(tmp_path):
    host, events, _ = make_host(tmp_path)
    host.attach("tui", "tui")
    assert host.command("mode", ["auto"], "tui")
    assert host.wait_idle(5)
    assert host.session.ctx.gates.mode == "ask"
    assert any("Confirm auto mode" in e.get("text", "") for e in events)
    assert host.command("mode", ["auto", "confirm"], "tui")
    assert host.wait_idle(5)
    assert host.session.ctx.gates.mode == "auto"
    assert any(e["type"] == "mode" and e["person"] == "tui" for e in host.session.ctx.log.events())
    host.close()


def test_review_in_auto_still_waits_for_a_human(tmp_path):
    host, events, arrived = make_host(tmp_path, "auto")
    host.attach("tui", "tui")
    host.session.ctx.ws.findings["f"] = ProposedFinding("f", "c", "Proposal", "CWE-89", [], "", "")
    host.command("review", [], "tui")
    assert arrived.wait(5)
    request = host.state()["pending"]
    assert request["gate"] == "G5"
    assert host.session.ctx.ws.findings["f"].status == "proposed"
    assert host.reply("tui", {"request_id": request["request_id"], "choice": "confirm"})["ok"]
    assert host.wait_idle(5)
    assert host.session.ctx.ws.findings["f"].status == "confirmed"
    assert next(e for e in events if e["type"] == "gate_result")["mode"] == "auto"
    host.close()


def test_resume_restores_log_totals_and_workspace_then_asks_g0(tmp_path):
    host, _, arrived = make_host(tmp_path)
    host.attach("tui", "tui")
    ctx = host.session.ctx
    ctx.ws.candidates["c"] = Candidate("c", "CWE-89", "sql", "A.java", 1, "x")
    ctx.ws.findings["f"] = ProposedFinding("f", "c", "Proposal", "CWE-89", [], "", "")
    ctx.ws.fixes["x"] = FixProposal("x", "f", "diff", status="deferred")
    ctx.log.append({"type": "usage", "input_tokens": 3, "output_tokens": 2, "cost_usd": 0.5})
    host.session.snapshot()
    original = ctx.log.path
    # Copy to a separate log so resume must actually replace the current log.
    saved = tmp_path / "saved.jsonl"
    saved.write_text(original.read_text())
    ctx.ws.findings.clear()
    ctx.ws.candidates.clear()
    ctx.ws.fixes.clear()
    host.command("resume", [str(saved)], "tui")
    assert arrived.wait(5)
    assert host.session.ctx.log.path == saved
    assert host.state()["totals"]["cost_usd"] == 0.5
    assert "c" in host.session.ctx.ws.candidates
    assert "f" in host.session.ctx.ws.findings
    assert "x" in host.session.ctx.ws.fixes
    request = host.state()["pending"]
    assert request["gate"] == "G0"
    host.reply("tui", {"request_id": request["request_id"], "choice": "reject"})
    assert host.wait_idle(5)
    assert not host.started
    assert any(e["type"] == "gate" for e in SessionLog(saved).events())
    host.close()


def test_findings_command_emits_only_harness_proposals(tmp_path):
    host, events, _ = make_host(tmp_path)
    host.attach("tui", "tui")
    host.session.ctx.ws.findings["f"] = ProposedFinding("f", "c", "Proposal", "CWE-89", [], "", "")
    host.command("findings", [], "tui")
    assert host.wait_idle(5)
    result = next(e for e in events if e["type"] == "findings")
    assert result["items"][0]["status"] == "proposed"
    host.close()


def test_help_cost_clear_and_export_commands(tmp_path):
    host, events, _ = make_host(tmp_path)
    host.attach("tui", "tui")
    for name, args in [
        ("help", []),
        ("cost", []),
        ("clear", []),
        ("export", [str(tmp_path / "report")]),
    ]:
        assert host.command(name, args, "tui")
        assert host.wait_idle(5)
    assert host.session.messages == []
    assert (tmp_path / "report/report.json").is_file()
    assert any("/resume" in e.get("text", "") for e in events)
    assert any(e["type"] == "usage" and e["total_tokens"] == 0 for e in events)
    host.close()


def test_remote_on_off_emits_link_and_off_events(tmp_path, monkeypatch):
    host, events, _ = make_host(tmp_path)

    class Server:
        def __init__(self, session_host):
            assert session_host is host
            self.url = "http://127.0.0.1:1234/app/remote#t=fixture"

        def start(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr("vulnscan.harness.remote.RemoteServer", Server)
    controller = RPCController(lambda e: None, host)
    for action in ["on", "off"]:
        assert controller.handle(
            {"protocol": PROTOCOL, "type": "command", "name": "remote", "args": [action]}
        )["ok"]
    remote = [e for e in events if e["type"] == "remote"]
    assert remote[0]["url"].endswith("#t=fixture") and remote[1]["off"]
    controller.close()
