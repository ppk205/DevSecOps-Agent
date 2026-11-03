"""Promote verified model-only hunt candidates to scanner-grade Findings.

Hunt mode buckets model candidates against scanner findings
(:func:`vulnscan.ai.compare.compare_hunt_vs_scanners`): agreed candidates
already have a scanner Finding, but model-only candidates would otherwise
die silently. Promotion re-reads each candidate's location through the
same jailed excerpt reader the hunt and review lanes use, and synthesizes
one ``UNPROCESSED`` Finding per candidate that still has real source
evidence behind it.

Drop rules: non-dict items, missing or non-string files, files that escape
the snapshot, unreadable or empty excerpts, and invalid (non-integer or
< 1) lines are skipped. Promotion never raises: one bad candidate never
kills the batch. Severity falls back to ``MEDIUM`` when the candidate
value is not a :class:`Severity` member; an unmappable CWE becomes
``UNCLASSIFIED`` on the finding (``None`` on the observation).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.ai.compare import norm_path
from vulnscan.ai.excerpts import code_excerpt
from vulnscan.contracts.enums import (
    CWECategory,
    EvidenceStrength,
    FindingProvenance,
    FindingStatus,
    Severity,
    ToolName,
    language_from_extension,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.scanners.mapping import confidence_value
from vulnscan.scanners.mapping import cwe_category as map_cwe_category

#: Sentinel returned by :func:`code_excerpt` when no source is readable.
_NO_EXCERPT = "(no source excerpt available)"

logger = logging.getLogger(__name__)

_MODEL_RULE_ID = "model-hunt"

# The contracts enum has no model member yet; rule_id + origin metadata
# carry the model provenance until one exists.
_candidate_tool: object = getattr(ToolName, "MODEL_HUNT", None)
_MODEL_TOOL: ToolName = (
    _candidate_tool if isinstance(_candidate_tool, ToolName) else ToolName.SEMGREP
)


def _candidate_line(candidate: dict[str, Any]) -> int | None:
    """1-based source line, or None when the candidate line is invalid."""
    try:
        line = int(candidate.get("line", 0))
    except (TypeError, ValueError):
        return None
    return line if line >= 1 else None


def _inside_snapshot(snapshot_root: str, file_path: str) -> bool:
    """True when *file_path* resolves inside *snapshot_root*."""
    try:
        root = Path(snapshot_root).resolve()
        target = (root / file_path).resolve()
        target.relative_to(root)
    except (OSError, ValueError, RuntimeError):
        return False
    return True


def _severity_of(candidate: dict[str, Any]) -> Severity:
    """Candidate severity, or MEDIUM when it is not a Severity member."""
    try:
        return Severity(str(candidate.get("severity", "medium")).strip().lower())
    except ValueError:
        return Severity.MEDIUM


def _promote_one(candidate: Any, *, snapshot_root: str, run_id: str) -> Finding | None:
    """Build one model-origin Finding, or None when the candidate drops."""
    if not isinstance(candidate, dict):
        return None
    raw_file = candidate.get("file")
    if not isinstance(raw_file, str) or not raw_file.strip():
        return None
    line = _candidate_line(candidate)
    if line is None or not _inside_snapshot(snapshot_root, raw_file):
        return None
    excerpt = code_excerpt(snapshot_root, raw_file, line)
    if not excerpt or excerpt == _NO_EXCERPT:
        return None

    norm_file = norm_path(raw_file)
    cwe_label = str(candidate.get("cwe") or "")
    mapped = map_cwe_category(cwe_label or None)
    severity = _severity_of(candidate)
    title = str(candidate.get("title") or "").strip()
    rationale = str(candidate.get("rationale") or "")
    evidence = str(candidate.get("evidence") or "")
    cwe_display = mapped.value if mapped is not None else (cwe_label.strip() or "CWE-unknown")
    if not title:
        title = f"{cwe_display} at {norm_file}:{line}"
    now = datetime.now(UTC)
    digest = hashlib.sha256(
        f"{norm_file}|{line}|{cwe_display}|{_MODEL_RULE_ID}".encode()
    ).hexdigest()
    finding_id = f"model-{digest[:16]}"
    observation_id = f"{finding_id}-obs"
    observation = Observation(
        observation_id=observation_id,
        run_id=run_id,
        tool=_MODEL_TOOL,
        tool_version=_MODEL_RULE_ID,
        rule_id=_MODEL_RULE_ID,
        cwe_category=mapped,
        severity=severity,
        message=(rationale.strip() or title)[:2000],
        confidence=confidence_value(candidate.get("laya_confidence"), default=1.0),
        location=SourceCoordinate(
            file_path=norm_file,
            language=language_from_extension(norm_file),
            line_start=line,
            snippet=excerpt[:2000],
        ),
        detected_at=now,
        metadata={"model_tool": _MODEL_RULE_ID},
    )
    return Finding(
        finding_id=finding_id,
        run_id=run_id,
        fingerprint=digest,
        title=title[:500],
        description=rationale[:2000],
        cwe_category=mapped if mapped is not None else CWECategory.UNCLASSIFIED,
        severity=severity,
        status=FindingStatus.UNPROCESSED,
        provenance=FindingProvenance.MODEL,
        observations=[observation],
        evidence_strength=EvidenceStrength.NONE,
        evidence_refs=[observation_id],
        created_at=now,
        updated_at=now,
        metadata={
            "title": title[:500],
            "rationale": rationale[:2000],
            "evidence": evidence[:2000],
        },
    )


def promote_model_only(
    model_only: list[dict[str, Any]],
    *,
    snapshot_root: str,
    run_id: str,
) -> list[Finding]:
    """Promote model-only candidates with readable source evidence.

    Every returned Finding carries top-level ``provenance == MODEL``.
    Never raises: bad items are skipped.
    """
    promoted: list[Finding] = []
    for candidate in model_only or []:
        try:
            finding = _promote_one(candidate, snapshot_root=snapshot_root, run_id=run_id)
        except Exception as exc:  # noqa: BLE001 - one bad candidate never kills promotion
            logger.debug("skipping unpromotable candidate: %s", exc)
            continue
        if finding is not None:
            promoted.append(finding)
    return promoted
