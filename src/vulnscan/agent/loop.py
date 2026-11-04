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
from itertools import islice
from typing import Any

from vulnscan.contracts.assessment import Assessment, CVSSAssessment
from vulnscan.contracts.finding import Finding
from vulnscan.providers.budget import BudgetExhausted
from vulnscan.providers.client import ChatMessage, ChatResponse, ProviderClient, ProviderError
from vulnscan.providers.events import emit_model_event

from .tools import TOOL_NAME_SET, TOOL_SCHEMAS

logger = logging.getLogger(__name__)

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


def _json_assessment(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    # ponytail: inspect at most 64 JSON starts to bound malformed model-output parsing.
    for start in islice(re.finditer(r"\{", text), 64):
        try:
            payload, _ = decoder.raw_decode(text, start.start())
        except (ValueError, RecursionError):
            continue
        if isinstance(payload, dict) and "proposed_status" in payload:
            return payload
    return None


def parse_verdict_text(text: str) -> tuple[str, float, str, bool]:
    """Extract (status, confidence, rationale, explicit) from free text.

    ``explicit`` is True only when the text carries an unambiguous verdict
    (JSON block or decisive keywords); otherwise the caller should treat
    the assessment as hollow and escalate (single-shot fallback / human).
    """
    status = "unresolved"
    confidence = 0.5
    rationale = text
    explicit = False

    parsed = _json_assessment(text)
    if parsed is not None:
        try:
            status = str(parsed.get("proposed_status", "unresolved")).lower()
            confidence = float(parsed.get("confidence", 0.5))
            rationale = str(parsed.get("rationale", text))
            explicit = True
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    if not explicit:
        lowered = text.lower()
        decisive_confirm = ("confirmed", "true positive", "true-positive", "exploitable")
        decisive_reject = (
            "rejected",
            "false positive",
            "false-positive",
            "not exploitable",
            "safe to ignore",
        )
        if any(k in lowered for k in decisive_confirm) and not any(
            k in lowered for k in decisive_reject
        ):
            status, explicit = "confirmed", True
        elif any(k in lowered for k in decisive_reject) and not any(
            k in lowered for k in decisive_confirm
        ):
            status, explicit = "rejected", True
        conf_match = re.search(r"confidence\s*[:=]?\s*(0?\.\d+|1\.0|1|0)", lowered)
        if conf_match:
            try:
                confidence = max(0.0, min(1.0, float(conf_match.group(1))))
            except ValueError:
                pass
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence = 0.5
    return status, confidence, (rationale or text)[:2000], explicit


def parse_cvss_and_assumptions(text: str) -> tuple[CVSSAssessment | None, list[str], list[str]]:
    """Compute a supplied vector; retain assumptions as unverified model data."""
    payload = _json_assessment(text)
    if payload is None:
        return None, [], []
    raw_assumptions = payload.get("assumptions", [])
    assumptions = (
        [value for value in raw_assumptions if isinstance(value, str)]
        if isinstance(raw_assumptions, list)
        else []
    )
    vector = payload.get("cvss_vector")
    if vector is None or vector == "":
        return None, assumptions, []
    if not isinstance(vector, str):
        return None, assumptions, ["CVSS proposal must be a complete v4.0 vector string"]
    from vulnscan.assessment.cvss import validate

    errors = validate(vector)
    if errors:
        return None, assumptions, errors
    return CVSSAssessment(vector=vector, source="ai-proposal"), assumptions, []


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
                model=self.model_id if self.model_id != "unknown" else None,
                tools=TOOL_SCHEMAS if step < self.max_followups else None,
                tool_choice="auto" if step < self.max_followups else "none",
            )

            total_tokens += resp.usage.get("total_tokens", 0)

            if not resp.tool_calls:
                return self._parse_assessment(resp, finding, tool_calls_made, total_tokens)

            messages.append(
                ChatMessage(
                    role="assistant",
                    content=resp.content or "",
                    tool_calls=resp.tool_calls,
                )
            )

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

                messages.append(
                    ChatMessage(
                        role="tool",
                        content=json.dumps(tool_result),
                        tool_call_id=tc["id"],
                    )
                )
                emit_model_event(
                    "tool",
                    "failed" if "error" in tool_result else "completed",
                    f"Investigation tool {tool_name}: "
                    + ("failed or rejected" if "error" in tool_result else "completed"),
                    provider=self.provider_id,
                    model=self.model_id,
                )
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
            "confidence, rationale, assumptions, cvss_vector (if evidence supports it). "
            "A CVSS v4.0 vector requires AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA in that order; "
            "use UI:N/P/A and AT:N/P. Do not invent unknown metric values or numeric scores; "
            "omit the vector when the evidence does not support a complete assessment."
        )

    def _parse_assessment(
        self,
        resp: ChatResponse,
        finding: Finding,
        tool_calls: int,
        total_tokens: int,
    ) -> Assessment:
        """Parse the final LLM response into an Assessment proposal."""
        proposed_status, confidence, rationale, explicit = parse_verdict_text(resp.content)
        cvss, assumptions, cvss_errors = parse_cvss_and_assumptions(resp.content)

        now = datetime.now(UTC)
        return Assessment(
            assessment_id=f"assess-{finding.finding_id}-ai",
            finding_id=finding.finding_id,
            run_id=finding.run_id,
            proposed_status=proposed_status,
            rationale=rationale[:2000],
            cvss=cvss,
            assumptions=assumptions,
            evidence_refs=[o.observation_id for o in finding.observations],
            confidence=confidence,
            provider_id=self.provider_id,
            model_id=self.model_id,
            model_version=self.model_version,
            created_at=now,
            metadata={
                "tool_calls_made": tool_calls,
                "total_tokens": total_tokens,
                "verdict_explicit": explicit,
                "cvss_validation_errors": cvss_errors,
                "cvss_score_status": "computed"
                if cvss is not None
                else "invalid"
                if cvss_errors
                else "not_provided",
            },
        )
