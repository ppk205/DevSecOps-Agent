"""Laya triage over harness candidates.

Laya runs before the model reads anything and only decides which route a
candidate needs. It never sets a finding's status. Without scanners in the
pipeline, the state Laya sees is built from the candidate itself.
"""

from __future__ import annotations

import logging
from typing import Any

from vulnscan.contracts.decision import DecisionRoute, DecisionStatus
from vulnscan.decisions.batching import triage_many_batched
from vulnscan.decisions.config import LayaConfig
from vulnscan.decisions.laya import LayaDecisionBackend
from vulnscan.decisions.triage import build_excerpt, build_triage_questions

from .workspace import Candidate

__all__ = ["candidate_state", "triage_candidates"]

_LOGGER = logging.getLogger(__name__)


def candidate_state(candidate: Candidate) -> dict[str, Any]:
    """Project a candidate into the bounded state Laya is allowed to see."""
    excerpt, truncated = build_excerpt(candidate.snippet)
    return {
        "finding_id": candidate.id,
        "run_id": "harness",
        "cwe_category": candidate.cwe,
        "severity": "undetermined",
        "evidence_strength": "weak",
        "tool_names": ["harness"],
        "observation_count": 1,
        "rule_ids": [candidate.kind],
        "file_path": candidate.file,
        "line_start": candidate.line,
        "language": "jsp" if candidate.file.endswith(".jsp") else "java",
        "code_excerpt": excerpt,
        "excerpt_truncated": truncated,
        "has_request_source": candidate.has_source,
        "has_auth_check": candidate.has_auth_check,
        "servlet_route": candidate.route or "",
    }


def _human_review(reason: str) -> DecisionRoute:
    return DecisionRoute(
        route="human_review",
        confidence=None,
        affects_finding_status=False,
        status=DecisionStatus.UNAVAILABLE,
        reasons=[reason],
    )


def triage_candidates(
    cands: list[Candidate],
    config: LayaConfig,
    agent: Any | None = None,
) -> dict[str, DecisionRoute]:
    """Route every candidate with Laya; never raises, never sets status."""
    routes: dict[str, DecisionRoute] = {}
    if not cands:
        return routes

    backend = agent
    reason = "no route returned"
    outcomes = []
    try:
        if backend is None:
            backend = LayaDecisionBackend(
                model_id=config.model_id,
                model_revision=config.revision,
                device="cpu",
                max_input_tokens=config.max_input_tokens,
                timeout_seconds=float(config.timeout_seconds),
            )
        outcomes = triage_many_batched(
            cands,
            backend,
            build_triage_questions(),
            batch_size=config.batch_size,
            to_state=candidate_state,
        )
    except Exception as exc:
        _LOGGER.warning("Laya triage failed; every candidate goes to human review", exc_info=True)
        reason = f"triage failed: {exc}"

    by_id = {outcome.finding_id: outcome for outcome in outcomes}
    for candidate in cands:
        outcome = by_id.get(candidate.id)
        if outcome is None or outcome.result.status is not DecisionStatus.COMPLETED:
            candidate.laya_route = "human_review"
            candidate.laya_confidence = None
            routes[candidate.id] = _human_review(reason)
            continue
        candidate.laya_route = outcome.route.route
        candidate.laya_confidence = outcome.route.confidence
        routes[candidate.id] = outcome.route
    return routes
