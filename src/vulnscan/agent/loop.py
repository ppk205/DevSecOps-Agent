"""Bounded investigation loop — the agentic analysis core.

Limits:
- Maximum 5 follow-up tool calls per finding (default, configurable).
- Only registered tools from ``tools.TOOL_SCHEMAS`` may be invoked.
- No provider credentials or evaluation labels in context.
- Provider failure or budget exhaustion preserves baseline scanner findings.
- Proposals are emitted for T05 validation; never final decisions.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from vulnscan.contracts.assessment import Assessment, CVSSAssessment
from vulnscan.contracts.finding import Finding
from vulnscan.providers.budget import BudgetExhausted
from vulnscan.providers.client import ChatMessage, ChatResponse, ProviderClient, ProviderError

from .tools import TOOL_NAME_SET, TOOL_SCHEMAS

logger = logging.getLogger(__name__)

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


class AgentLoop:
    """Run the bounded investigation for a single finding.

    Parameters
    ----------
    client:
        Configured :class:`ProviderClient` with budget enforcement.
    tool_handlers:
        Map of tool name → callable that executes it locally.
    max_followups:
        Maximum tool-call rounds before the loop yields (default 5).
    """

    def __init__(
        self,
        client: ProviderClient,
        tool_handlers: dict[str, ToolHandler],
        max_followups: int = 5,
        *,
        provider_id: str = "unknown",
        model_id: str = "unknown",
        model_version: str = "v1",
    ) -> None:
        self.client = client
        self.tool_handlers = tool_handlers
        self.max_followups = max_followups
        self.provider_id = provider_id
        self.model_id = model_id
        self.model_version = model_version

    def investigate(self, finding: Finding, context: dict[str, Any]) -> Assessment:
        """Run the bounded loop for *finding* and return an Assessment proposal.

        On provider failure or budget exhaustion the baseline scanner findings
        are preserved and an ``unresolved`` assessment is returned.
        """
        try:
            return self._run_loop(finding, context)
        except (ProviderError, BudgetExhausted) as exc:
            logger.warning("Agent loop failed for %s: %s", finding.finding_id, exc)
            now = datetime.now(UTC)
            return Assessment(
                assessment_id=f"assess-{finding.finding_id}-unresolved",
                finding_id=finding.finding_id,
                run_id=finding.run_id,
                proposed_status="unresolved",
                rationale=f"Provider/budget error: {exc}",
                evidence_refs=[o.observation_id for o in finding.observations],
                confidence=0.0,
                provider_id=self.provider_id,
                model_id=self.model_id,
                model_version=self.model_version,
                created_at=now,
                metadata={
                    "error": str(exc),
                    "tool_calls_made": 0,
                    "total_tokens": 0,
                },
            )

    def _run_loop(self, finding: Finding, context: dict[str, Any]) -> Assessment:
        system_prompt = self._build_system_prompt(finding, context)
        messages: list[ChatMessage] = [
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(role="user", content=self._build_user_prompt(finding)),
        ]

        tool_calls_made = 0
        total_tokens = 0

        for step in range(self.max_followups + 1):
            resp: ChatResponse = self.client.chat(
                messages,
                tools=TOOL_SCHEMAS if step < self.max_followups else None,
                tool_choice="auto" if step < self.max_followups else "none",
            )

            total_tokens += resp.usage.get("total_tokens", 0)

            if not resp.tool_calls:
                return self._parse_assessment(resp, finding, tool_calls_made, total_tokens)

            messages.append(ChatMessage(
                role="assistant",
                content=resp.content or "",
                tool_calls=resp.tool_calls,
            ))

            for tc in resp.tool_calls:
                tool_name = tc["function"]["name"]
                if tool_name not in TOOL_NAME_SET:
                    tool_result = {"error": f"Tool '{tool_name}' is not registered."}
                else:
                    try:
                        args = json.loads(tc["function"]["arguments"])
                        handler = self.tool_handlers.get(tool_name)
                        if handler:
                            tool_result = handler(args)
                        else:
                            tool_result = {"error": f"No handler for tool '{tool_name}'."}
                    except Exception as exc:  # noqa: BLE001 - arbitrary tool handler boundary
                        logger.warning("Tool %s failed: %s", tool_name, exc)
                        tool_result = {"error": str(exc)}

                messages.append(ChatMessage(
                    role="tool",
                    content=json.dumps(tool_result),
                    tool_call_id=tc["id"],
                ))
                tool_calls_made += 1

        # Exhausted follow-ups
        now = datetime.now(UTC)
        return Assessment(
            assessment_id=f"assess-{finding.finding_id}-partial",
            finding_id=finding.finding_id,
            run_id=finding.run_id,
            proposed_status="unresolved",
            rationale=f"Exhausted {self.max_followups} follow-up calls without final assessment.",
            evidence_refs=[o.observation_id for o in finding.observations],
            confidence=0.0,
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_version=self.model_version,
            created_at=now,
            metadata={"tool_calls_made": tool_calls_made, "total_tokens": total_tokens},
        )

    def _build_system_prompt(self, finding: Finding, context: dict[str, Any]) -> str:
        return (
            "You are a security analyst assistant helping triage and assess "
            "vulnerability findings in Java Servlet/JSP source code.\n\n"
            "RULES:\n"
            "- You may ONLY use the registered tools provided.\n"
            "- Do not fabricate source code, file contents, or evidence.\n"
            "- If information is missing, say so explicitly.\n"
            "- Propose CVSS v4.0 vectors only when evidence supports the metrics.\n"
            "- Never access evaluation labels, expected findings, or ground truth.\n"
            "- Your output is a PROPOSAL, not a final decision.\n"
            "- Missing evidence means 'unknown', never 'safe'.\n\n"
            f"Security policy context:\n{json.dumps(context.get('policy', {}), indent=2)}\n\n"
            f"Source index context:\n{json.dumps(context.get('source_index', {}), indent=2)[:2000]}"
        )

    def _build_user_prompt(self, finding: Finding) -> str:
        obs_summary = "\n".join(
            f"- [{o.tool.value}] {o.rule_id}: {o.message} "
            f"({o.location.file_path}:{o.location.line_start})"
            if o.location
            else f"- [{o.tool.value}] {o.rule_id}: {o.message}"
            for o in finding.observations
        )
        return (
            f"Analyze finding {finding.finding_id}:\n"
            f"  Title: {finding.title}\n"
            f"  CWE: {finding.cwe_category.value if finding.cwe_category else 'unknown'}\n"
            f"  Severity: {finding.severity.value}\n"
            f"  Fingerprint: {finding.fingerprint}\n\n"
            f"Scanner observations:\n{obs_summary}\n\n"
            "Use the available tools to inspect source code, look up routes, "
            "retrieve evidence, and check coverage before making your assessment. "
            "End with a JSON assessment block containing: proposed_status, "
            "confidence, rationale, cvss_vector (if evidence supports it)."
        )

    def _parse_assessment(
        self,
        resp: ChatResponse,
        finding: Finding,
        tool_calls: int,
        total_tokens: int,
    ) -> Assessment:
        """Parse the final LLM response into an Assessment proposal."""
        proposed_status = "unresolved"
        confidence = 0.5
        rationale = resp.content
        cvss_vector = None

        json_match = re.search(r'\{[^{}]*"proposed_status"[^{}]*\}', resp.content, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                proposed_status = parsed.get("proposed_status", "unresolved")
                confidence = float(parsed.get("confidence", 0.5))
                rationale = parsed.get("rationale", resp.content)
                cvss_vector = parsed.get("cvss_vector")
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

        cvss = None
        if cvss_vector:
            try:
                cvss = CVSSAssessment(vector=str(cvss_vector), source="ai-proposal")
            except (TypeError, ValueError) as exc:
                logger.debug("Ignoring invalid AI CVSS proposal %r: %s", cvss_vector, exc)

        now = datetime.now(UTC)
        return Assessment(
            assessment_id=f"assess-{finding.finding_id}-ai",
            finding_id=finding.finding_id,
            run_id=finding.run_id,
            proposed_status=proposed_status,
            rationale=rationale[:2000],
            cvss=cvss,
            evidence_refs=[o.observation_id for o in finding.observations],
            confidence=confidence,
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_version=self.model_version,
            created_at=now,
            metadata={"tool_calls_made": tool_calls, "total_tokens": total_tokens},
        )
