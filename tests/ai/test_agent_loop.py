"""T04 gate: bounded agent loop — max followups, tool rejection, budget."""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

from vulnscan.agent.loop import AgentLoop
from vulnscan.contracts.assessment import Assessment
from vulnscan.contracts.enums import (
    CWECategory,
    FindingStatus,
    ProviderProtocol,
    Severity,
    ToolName,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.providers.budget import BudgetExhausted
from vulnscan.providers.client import ChatResponse, ProviderClient


def _finding(fid: str = "f1") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id=fid,
        run_id="r1",
        fingerprint="fp-test",
        title="SQL Injection in login",
        description="User input flows to query",
        cwe_category=CWECategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=FindingStatus.UNPROCESSED,
        observations=[
            Observation(
                observation_id="obs-1",
                detected_at=now,
                run_id="r1",
                tool=ToolName.SEMGREP,
                tool_version="1.0",
                rule_id="java.lang.security.audit.sqli",
                cwe_category=CWECategory.SQL_INJECTION,
                severity=Severity.HIGH,
                message="SQL injection via request param",
                confidence=0.9,
                location=SourceCoordinate(file_path="src/LoginServlet.java", line_start=42),
            )
        ],
        created_at=now,
        updated_at=now,
    )


def _mock_provider_client(responses: list[ChatResponse]) -> ProviderClient:
    """Create a ProviderClient with mocked chat method."""
    profile = ProviderProfile(
        id="test", label="Test", protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        base_url="https://api.test.com/v1", api_key_env="TEST_KEY",
        models=["m"], default_model="m",
    )
    client = MagicMock(spec=ProviderClient)
    client.profile = profile
    client.chat = MagicMock(side_effect=responses)
    return client


class TestAgentLoop:
    def test_no_tool_calls(self):
        """Agent returns assessment without tool calls."""
        final_resp = ChatResponse(
            content=json.dumps({
                "proposed_status": "confirmed",
                "confidence": 0.85,
                "rationale": "Strong evidence of SQL injection",
            }),
            tool_calls=[],
            usage={"total_tokens": 100},
            model="gpt-4o",
        )
        client = _mock_provider_client([final_resp])
        loop = AgentLoop(client, {}, max_followups=5)
        assessment = loop.investigate(_finding(), {})

        assert assessment.proposed_status == "confirmed"
        assert assessment.confidence == 0.85
        assert isinstance(assessment, Assessment)

    def test_max_followups_respected(self):
        """Loop stops after max_followups tool-call rounds."""
        tool_call = {
            "id": "tc-1",
            "type": "function",
            "function": {"name": "inspect_code", "arguments": '{"file_path":"x.java"}'},
        }
        tool_resp = ChatResponse(content="", tool_calls=[tool_call], usage={}, model="m")
        final_resp = ChatResponse(
            content=json.dumps({"proposed_status": "unresolved", "confidence": 0.3, "rationale": "need more info"}),
            tool_calls=[],
            usage={"total_tokens": 50},
            model="m",
        )
        client = _mock_provider_client([tool_resp, tool_resp, final_resp])
        mock_handler = MagicMock(return_value={"content": "some code"})
        loop = AgentLoop(client, {"inspect_code": mock_handler}, max_followups=2)

        assessment = loop.investigate(_finding(), {})
        assert mock_handler.call_count == 2  # max_followups=2, so 2 tool calls
        assert assessment.proposed_status == "unresolved"

    def test_unregistered_tool_rejected(self):
        """Unregistered tools are rejected with error message."""
        tool_call = {
            "id": "tc-1",
            "type": "function",
            "function": {"name": "dangerous_tool", "arguments": "{}"},
        }
        tool_resp = ChatResponse(content="", tool_calls=[tool_call], usage={}, model="m")
        final_resp = ChatResponse(
            content=json.dumps({"proposed_status": "unresolved", "confidence": 0.1, "rationale": "tool rejected"}),
            tool_calls=[],
            usage={},
            model="m",
        )
        client = _mock_provider_client([tool_resp, final_resp])
        loop = AgentLoop(client, {}, max_followups=5)
        assessment = loop.investigate(_finding(), {})
        assert assessment.proposed_status == "unresolved"

    def test_budget_exhausted_returns_unresolved(self):
        """Budget exhaustion preserves findings as unresolved."""
        client = _mock_provider_client([])
        client.chat = MagicMock(side_effect=BudgetExhausted("no budget"))
        loop = AgentLoop(client, {}, max_followups=5)

        assessment = loop.investigate(_finding(), {})
        assert assessment.proposed_status == "unresolved"
        assert "budget" in assessment.rationale.lower() or "error" in assessment.rationale.lower()
