"""End-to-end tests for AI Agent calling the 5 scanner tools + CLI tool-scan."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from typer.testing import CliRunner

from vulnscan.agent.loop import AgentLoop
from vulnscan.agent.tools import SCANNER_TOOL_NAME_SET, TOOL_NAME_SET, TOOL_SCHEMAS
from vulnscan.ai.hunt import hunt_vulns
from vulnscan.ai.review import build_tool_handlers
from vulnscan.cli.main import app as cli_app
from vulnscan.contracts.enums import (
    CWECategory,
    FindingStatus,
    ProviderProtocol,
    Severity,
    ToolName,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.providers.client import ChatResponse, ProviderClient


def _make_finding() -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id="f-scan-1",
        run_id="r-scan-1",
        fingerprint="fp-scan-1",
        title="Command Injection in handler",
        description="Untrusted input passed to shell",
        cwe_category=CWECategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        status=FindingStatus.UNPROCESSED,
        observations=[
            Observation(
                observation_id="obs-scan-1",
                detected_at=now,
                run_id="r-scan-1",
                tool=ToolName.SEMGREP,
                tool_version="1.178.0",
                rule_id="python.lang.security.audit.subprocess-shell-true",
                cwe_category=CWECategory.COMMAND_INJECTION,
                severity=Severity.HIGH,
                message="subprocess call with shell=True",
                location=SourceCoordinate(file_path="app.py", line_start=3),
            )
        ],
        created_at=now,
        updated_at=now,
    )


def _mock_client(responses: list[ChatResponse]) -> ProviderClient:
    profile = ProviderProfile(
        id="test",
        label="Test",
        protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        base_url="https://api.test.com/v1",
        api_key_env="TEST_KEY",
        models=["test-model"],
        default_model="test-model",
    )
    client = ProviderClient(profile)
    client.chat = MagicMock(side_effect=responses)  # type: ignore[method-assign]
    return client


def _tool_call(name: str, args: dict, call_id: str) -> dict:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


class TestScannerToolRegistration:
    def test_all_seven_scanner_tools_registered_in_schemas(self) -> None:
        expected = {
            "run_semgrep_scan",
            "run_codeql_scan",
            "run_owasp_scan",
            "run_secret_scan",
            "run_config_audit",
            "query_scanner_findings",
            "explain_scanner_rule",
        }
        assert expected == SCANNER_TOOL_NAME_SET
        assert expected.issubset(TOOL_NAME_SET)
        names = {t["function"]["name"] for t in TOOL_SCHEMAS}
        assert expected.issubset(names)

    def test_build_tool_handlers_wires_all_scanner_tools(self, tmp_path: Path) -> None:
        handlers = build_tool_handlers(tmp_path, [_make_finding()])
        assert SCANNER_TOOL_NAME_SET.issubset(handlers.keys())
        # Verify query_scanner_findings sees the pre-existing finding
        q = handlers["query_scanner_findings"]({"tool": "semgrep", "cwe": "CWE-78"})
        assert q["total_matched"] == 1
        assert q["results"][0]["finding_id"] == "f-scan-1"


class TestAgentLoopScannerCalling:
    def test_agent_loop_invokes_live_semgrep_and_explain_rule(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            "import subprocess\ndef run(user_cmd):\n    subprocess.Popen(user_cmd, shell=True)\n",
            encoding="utf-8",
        )
        finding = _make_finding()
        handlers = build_tool_handlers(tmp_path, [finding])

        responses = [
            ChatResponse(
                content="",
                tool_calls=[
                    _tool_call(
                        "run_semgrep_scan",
                        {"target_path": "app.py", "language": "python"},
                        "tc-1",
                    ),
                    _tool_call(
                        "explain_scanner_rule",
                        {"rule_id": "python.lang.security.audit.subprocess-shell-true"},
                        "tc-2",
                    ),
                ],
                usage={"total_tokens": 120},
            ),
            ChatResponse(
                content=json.dumps(
                    {
                        "proposed_status": "confirmed",
                        "confidence": 0.95,
                        "rationale": "Confirmed via live Semgrep scan on app.py line 3.",
                    }
                ),
                tool_calls=[],
                usage={"total_tokens": 90},
            ),
        ]

        client = _mock_client(responses)
        loop = AgentLoop(client, handlers, max_followups=4)
        assessment = loop.investigate(finding, context={})

        assert assessment.proposed_status == "confirmed"
        assert assessment.confidence == 0.95
        assert assessment.metadata["tool_calls_made"] == 2

        # Verify tool messages injected back into LLM carried real Semgrep results
        second_call_messages = client.chat.call_args_list[1].args[0]
        tool_msgs = [m for m in second_call_messages if m.role == "tool"]
        assert len(tool_msgs) == 2
        semgrep_payload = json.loads(tool_msgs[0].content)
        assert semgrep_payload["status"] == "completed"
        assert semgrep_payload["returned"] >= 1
        explain_payload = json.loads(tool_msgs[1].content)
        assert "CWE-78" in explain_payload["cwe"]


class TestHuntWithScannerTools:
    def test_hunt_loop_can_call_run_semgrep_scan(self, tmp_path: Path) -> None:
        (tmp_path / "server.py").write_text(
            "import subprocess\ndef handler(cmd):\n    return subprocess.Popen(cmd, shell=True)\n",
            encoding="utf-8",
        )
        script = [
            # Turn 0 (fast-path): return empty so loop proceeds to tool-calling
            ChatResponse(content="[]", tool_calls=[], usage={"total_tokens": 10}),
            # Turn 1 (tool loop): AI decides to invoke run_semgrep_scan
            ChatResponse(
                content="",
                tool_calls=[
                    _tool_call(
                        "run_semgrep_scan",
                        {"target_path": "server.py", "language": "python"},
                        "h1",
                    )
                ],
                usage={"total_tokens": 25},
            ),
            # Turn 2: AI emits final confirmed candidate JSON array
            ChatResponse(
                content=json.dumps(
                    [
                        {
                            "title": "OS Command Injection via shell=True",
                            "file": "server.py",
                            "line": 3,
                            "cwe": "CWE-78",
                            "severity": "high",
                            "rationale": "Confirmed with Semgrep",
                            "evidence": "subprocess.Popen(cmd, shell=True)",
                        }
                    ]
                ),
                tool_calls=[],
                usage={"total_tokens": 30},
            ),
        ]

        class _ScriptClient:
            def chat(self, messages, **kwargs):
                return script.pop(0)

        res = hunt_vulns(
            snapshot_root=str(tmp_path),
            client=_ScriptClient(),  # type: ignore[arg-type]
            model="test-model",
            family="python",
            max_rounds=4,
        )
        assert res["status"] == "completed"
        assert len(res["candidates"]) == 1
        assert res["candidates"][0]["cwe"] == "CWE-78"


class TestCliToolScan:
    def test_cli_capabilities_and_explain(self, tmp_path: Path) -> None:
        (tmp_path / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
        runner = CliRunner()

        cap_res = runner.invoke(cli_app, ["tool-scan", "capabilities", "--root", str(tmp_path)])
        assert cap_res.exit_code == 0, cap_res.output
        cap_json = json.loads(cap_res.output)
        assert "go" in cap_json["detected_languages"]
        assert len(cap_json["supported_language_families"]) == 7
        assert set(cap_json["tools"].keys()) == {
            "semgrep",
            "codeql",
            "owasp",
            "gitleaks",
            "spotbugs",
            "trivy",
        }

        exp_res = runner.invoke(cli_app, ["tool-scan", "explain", "java.sqli", "--tool", "semgrep"])
        assert exp_res.exit_code == 0, exp_res.output
        exp_json = json.loads(exp_res.output)
        assert "CWE-89" in exp_json["cwe"]
