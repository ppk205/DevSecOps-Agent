"""Laya verification of model-hunted candidates.

Each hunted candidate becomes one ``DecisionRequest`` (candidate metadata +
a jailed 30-line source excerpt) sharing the frozen triage question set, and
the batch goes through ``LayaDecisionBackend.predict_many``. Results are
attached back onto copies of the candidates as advisory-only fields::

    {laya_route, laya_confidence, laya_status}

Laya is advisory here, exactly as in the shadow triage stage: it records a
route, never a finding status (status moves only via IndependentValidator).
When Laya is unavailable every item gets ``{"laya_status": "skipped"}``.
This function never raises.
"""

from __future__ import annotations

import logging
from typing import Any

from vulnscan.ai.excerpts import code_excerpt
from vulnscan.contracts.decision import DecisionRequest
from vulnscan.decisions.laya import LayaDecisionBackend
from vulnscan.decisions.protocol import QUESTION_SET_VERSION
from vulnscan.decisions.router import DecisionRouter
from vulnscan.decisions.triage import build_triage_questions

logger = logging.getLogger(__name__)

_SKIPPED = "skipped"


def _candidate_line(candidate: dict[str, Any]) -> int:
    try:
        return int(candidate.get("line", 0) or 0)
    except (TypeError, ValueError):
        return 0


def laya_verify_candidates(
    candidates: list[dict[str, Any]],
    *,
    snapshot_root: str,
    laya_config: LayaDecisionBackend | Any | None = None,
) -> list[dict[str, Any]]:
    """Verify hunted candidates with Laya; attach route/confidence/status.

    Args:
        candidates: hunt output items (title, file, line, cwe, severity,
            rationale, evidence).
        snapshot_root: immutable scan snapshot for jailed excerpts.
        laya_config: a ``LayaDecisionBackend`` to reuse, or None to build
            the default backend. Any other value is ignored (default used).

    Returns:
        New dicts (inputs untouched) with ``laya_route``,
        ``laya_confidence`` and ``laya_status`` attached. Laya failure
        (or construction failure) marks every item ``skipped``.
    """
    if not candidates:
        return []
    questions = build_triage_questions()
    requests: list[DecisionRequest] = []
    for candidate in candidates:
        excerpt = code_excerpt(
            snapshot_root, str(candidate.get("file", "")), _candidate_line(candidate)
        )
        state: dict[str, Any] = {
            "title": str(candidate.get("title", "")),
            "file_path": str(candidate.get("file", "")),
            "line_start": _candidate_line(candidate),
            "cwe": str(candidate.get("cwe", "")),
            "severity": str(candidate.get("severity", "")),
            "rationale": str(candidate.get("rationale", "")),
            "evidence": str(candidate.get("evidence", "")),
            "code_excerpt": excerpt,
            "is_this_exploitable": (
                f"Is this finding exploitable? {candidate.get('title', '')} "
                f"at {candidate.get('file', '')}:{_candidate_line(candidate)} "
                f"({candidate.get('cwe', 'unknown CWE')}). "
                f"Rationale: {candidate.get('rationale', '')}"
            ),
        }
        requests.append(
            DecisionRequest(
                state=state,
                questions=questions,
                question_set_version=QUESTION_SET_VERSION,
            )
        )

    backend: LayaDecisionBackend
    if isinstance(laya_config, LayaDecisionBackend):
        backend = laya_config
    else:
        try:
            backend = LayaDecisionBackend()
        except Exception as exc:  # noqa: BLE001 - verify stage must never raise
            logger.warning("laya backend unavailable, skipping verification: %s", exc)
            return [{**c, "laya_status": _SKIPPED} for c in candidates]

    try:
        results = backend.predict_many(requests)
    except Exception as exc:  # noqa: BLE001 - verify stage must never raise
        logger.warning("laya verification failed, marking skipped: %s", exc)
        return [{**c, "laya_status": _SKIPPED} for c in candidates]

    router = DecisionRouter()
    enriched: list[dict[str, Any]] = []
    for candidate, request, result in zip(candidates, requests, results, strict=True):
        try:
            route = router.route(request=request, result=result, final_status=None)
            enriched.append(
                {
                    **candidate,
                    "laya_route": route.route,
                    "laya_confidence": route.confidence,
                    "laya_status": result.status.value,
                }
            )
        except Exception as exc:  # noqa: BLE001 - one bad row must not fail the batch
            logger.warning("laya route mapping failed for a candidate: %s", exc)
            enriched.append({**candidate, "laya_status": _SKIPPED})
    return enriched
