"""AI review wiring: model verdicts on findings, owned by IndependentValidator.

Pipeline position (authoritative order):

```text
Deterministic evidence
        ↓
Laya batch routing        (advisory, skippable)
        ↓
Targeted deep analysis    (this module; optional, needs a provider profile)
        ↓
Independent validation    (IndependentValidator owns every status change)
        ↓
Human decision support    (report + dashboard)
```

Guarantees:
* No provider configured (or provider/budget failure) → stages report
  ``skipped``/``partial`` and every finding keeps its scanner status.
  The deterministic baseline is never degraded by AI.
* The model only *proposes* (Assessment). Only IndependentValidator moves
  a finding to confirmed/rejected/unresolved — via ValidationDecision.
* Tool handlers are read-only and jailed to the immutable scan snapshot:
  no shell, no network, no writes, no credentials in context.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.agent.loop import AgentLoop, parse_verdict_text
from vulnscan.agent.tools import TOOL_SCHEMAS  # noqa: F401  (re-exported for tests)
from vulnscan.ai.excerpts import code_excerpt_for_finding as _code_excerpt
from vulnscan.assessment.validator import IndependentValidator
from vulnscan.contracts.assessment import Assessment
from vulnscan.contracts.enums import (
    EvidenceKind,
    EvidenceStrength,
    FindingStatus,
)
from vulnscan.contracts.finding import Finding
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.contracts.validation import EvidenceRecord
from vulnscan.providers.budget import BudgetExhausted, BudgetManager
from vulnscan.providers.client import ProviderClient, ProviderError
from vulnscan.providers.credentials import CredentialError
from vulnscan.providers.profile_store import load_profile

logger = logging.getLogger(__name__)

# Routes that earn a (bounded, read-only) model investigation. Findings on
# any other route keep their deterministic status untouched.
DEEP_ANALYSIS_ROUTES = frozenset(
    {
        "cross_file_analysis",
        "jsp_context_analysis",
        "authorization_analysis",
    }
)


def _resolve_inside(root: Path, rel: str) -> Path | None:
    """Resolve *rel* inside *root*; None when it escapes the snapshot."""
    try:
        target = (root / rel).resolve()
    except (OSError, ValueError):
        return None
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None
    return target


def build_tool_handlers(
    snapshot_root: str | Path,
    findings: Sequence[Finding],
    coverage_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Local, read-only handlers for the agent's registered tools."""
    root = Path(snapshot_root)
    by_id = {f.finding_id: f for f in findings}
    coverage: dict[str, Any] = dict(coverage_summary or {})

    def inspect_code(args: dict[str, Any]) -> dict[str, Any]:
        rel = str(args.get("file_path", ""))
        target = _resolve_inside(root, rel)
        if target is None or not target.is_file():
            return {"error": f"path escapes the scan snapshot or is not a file: {rel[:200]}"}
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return {"error": f"cannot read {rel[:200]}: {exc}"}
        try:
            start = max(1, int(args.get("start_line", 1)))
        except (TypeError, ValueError):
            start = 1
        try:
            end = int(args.get("end_line", start + 40))
        except (TypeError, ValueError):
            end = start + 40
        end = min(len(lines), max(start, end))
        window = lines[start - 1 : end][:120]
        return {
            "file_path": target.relative_to(root.resolve()).as_posix(),
            "start_line": start,
            "end_line": end,
            "total_lines": len(lines),
            "content": "\n".join(window),
        }

    def get_evidence(args: dict[str, Any]) -> dict[str, Any]:
        finding = by_id.get(str(args.get("finding_id", "")))
        if finding is None:
            return {"error": "unknown finding id"}
        data: dict[str, Any] = json.loads(finding.model_dump_json())
        return data

    def check_coverage(args: dict[str, Any]) -> dict[str, Any]:
        cwe = str(args.get("cwe") or "")
        if cwe and isinstance(coverage, dict):
            return {k: v for k, v in coverage.items() if cwe.lower() in k.lower()}
        return coverage

    def lookup_route(args: dict[str, Any]) -> dict[str, Any]:
        return {
            "note": "route lookup is served from the scan manifest, not the live repo",
            "query": str(args.get("query", ""))[:200],
        }

    def propose_verification(args: dict[str, Any]) -> dict[str, Any]:
        return {
            "finding_id": str(args.get("finding_id", "")),
            "verification_level": str(args.get("verification_level", "static")),
            "procedure": (
                "confirm the sink is reachable with attacker-controlled data; "
                "check for sanitizers/validators on the path; "
                "a fixed variant must no longer match the rule at the same location."
            ),
        }

    def list_files(args: dict[str, Any]) -> dict[str, Any]:
        try:
            rel = str(args.get("dir", ".") or ".")
            target = _resolve_inside(root, rel)
            if target is None or not target.is_dir():
                return {
                    "error": f"path escapes the scan snapshot or is not a directory: {rel[:200]}"
                }
            glob = str(args.get("glob", "*.java") or "*.java")
            try:
                paths = sorted(
                    p.relative_to(root.resolve()).as_posix()
                    for p in target.rglob(glob)
                    if p.is_file()
                )
            except (OSError, ValueError) as exc:
                return {"error": f"cannot list {rel[:200]}: {exc}"}
            if len(paths) > 2000:
                return {"error": f"too many files match ({len(paths)} > 2000); narrow the glob"}
            return {"dir": rel[:200], "glob": glob[:200], "files": paths}
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"error": str(exc)[:500]}

    def grep_code(args: dict[str, Any]) -> dict[str, Any]:
        try:
            pattern = str(args.get("pattern", ""))
            if not pattern:
                return {"error": "missing required argument: pattern"}
            try:
                rx = re.compile(pattern)
            except re.error as exc:
                return {"error": f"invalid regex: {exc}"}
            glob = str(args.get("glob", "*.java") or "*.java")
            try:
                max_hits = int(args.get("max_hits", 20))
            except (TypeError, ValueError):
                max_hits = 20
            max_hits = max(1, min(50, max_hits))
            try:
                candidates = [p for p in root.rglob(glob) if p.is_file()]
            except (OSError, ValueError) as exc:
                return {"error": f"cannot scan snapshot: {exc}"}
            if len(candidates) > 2000:
                return {
                    "error": f"too many files match ({len(candidates)} > 2000); narrow the glob"
                }
            resolved = root.resolve()
            hits: list[dict[str, Any]] = []
            for path in sorted(candidates):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        hits.append(
                            {
                                "file": path.relative_to(resolved).as_posix(),
                                "line": lineno,
                                "text": line.strip()[:500],
                            }
                        )
                        if len(hits) >= max_hits:
                            break
                if len(hits) >= max_hits:
                    break
            return {
                "pattern": pattern[:500],
                "hits": hits,
                "truncated": len(hits) >= max_hits,
            }
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"error": str(exc)[:500]}

    return {
        "inspect_code": inspect_code,
        "get_evidence": get_evidence,
        "check_coverage": check_coverage,
        "lookup_route": lookup_route,
        "propose_verification": propose_verification,
        "list_files": list_files,
        "grep_code": grep_code,
    }


def build_review_agent(
    profile_id: str,
    tool_handlers: dict[str, Any],
    model: str | None = None,
    budget: BudgetManager | None = None,
    max_followups: int = 5,
) -> tuple[AgentLoop, ProviderClient, ProviderProfile, BudgetManager]:
    """Build a bounded AgentLoop from a stored provider profile (BYOK).

    The API key is read from the environment variable named by the profile
    at call time; it is never stored, logged, or embedded in any artifact.
    """
    profile = load_profile(profile_id)
    selected_model = model or profile.default_model or next(iter(profile.models), None)
    if not selected_model:
        raise ProviderError("The selected provider profile has no configured model")
    own_budget = budget or BudgetManager()
    client = ProviderClient(profile, own_budget)
    loop = AgentLoop(
        client,
        tool_handlers,
        max_followups=max_followups,
        provider_id=profile.id,
        model_id=selected_model,
        model_version="v1",
    )
    return loop, client, profile, own_budget


def single_shot_verdict(
    client: ProviderClient,
    finding: Finding,
    snapshot_root: str,
    profile: ProviderProfile,
    model: str | None,
) -> Assessment | None:
    """One bounded call with embedded evidence — for models without tool use.

    Returns None when the reply carries no usable verdict.
    """
    from vulnscan.providers.client import ChatMessage

    obs_lines = []
    for o in finding.observations:
        loc = f"{o.location.file_path}:{o.location.line_start}" if o.location else "?"
        snippet = (o.location.snippet if o.location and o.location.snippet else "").strip()
        obs_lines.append(f"- [{o.tool.value}] {o.rule_id}: {o.message} @ {loc}")
        if snippet:
            obs_lines.append(f"  evidence: {snippet[:600]}")
    prompt = (
        "You are a security analyst triaging ONE static-analysis finding. "
        "Use only the evidence below; do not invent code. "
        "Reply with a single JSON object and nothing else.\n\n"
        f"Title: {finding.title}\n"
        f"CWE: {finding.cwe_category.value if finding.cwe_category else 'unknown'}\n"
        f"Severity: {finding.severity.value}\n"
        "Scanner observations:\n" + "\n".join(obs_lines) + "\n\n"
        "Source excerpt:\n" + _code_excerpt(snapshot_root, finding) + "\n\n"
        'JSON schema: {"proposed_status": "confirmed|rejected|unresolved", '
        '"confidence": 0.0-1.0, "rationale": "one or two sentences"}'
    )
    try:
        resp = client.chat(
            [ChatMessage(role="user", content=prompt)],
            model=model or profile.default_model,
            max_tokens=600,
        )
    except (ProviderError, BudgetExhausted, CredentialError):
        return None
    status, confidence, rationale, explicit = parse_verdict_text(resp.content)
    if not explicit:
        return None
    now = datetime.now(UTC)
    return Assessment(
        assessment_id=f"assess-{finding.finding_id}-single",
        finding_id=finding.finding_id,
        run_id=finding.run_id,
        proposed_status=status,
        rationale=rationale,
        evidence_refs=[o.observation_id for o in finding.observations],
        confidence=confidence,
        provider_id=profile.id,
        model_id=resp.model or model or profile.default_model or "unknown",
        model_version="v1",
        created_at=now,
        metadata={"single_shot": True, "total_tokens": resp.usage.get("total_tokens", 0)},
    )


def pick_review_targets(
    findings: Sequence[Finding],
    routing: Sequence[dict[str, Any]],
    max_findings: int,
) -> list[Finding]:
    """Deep-lane findings first, then the rest — always bounded.

    Bounding matters on metered/free-tier gateways where every agent turn
    is a billable request.
    """
    route_by_id = {str(p.get("finding_id")): str(p.get("route", "")) for p in routing}
    deep = [f for f in findings if route_by_id.get(f.finding_id) in DEEP_ANALYSIS_ROUTES]
    rest = [f for f in findings if f not in deep]
    ordered = [
        f for f in deep + rest if f.status in (FindingStatus.UNPROCESSED, FindingStatus.TRIAGED)
    ]
    return ordered[: max(0, max_findings)]


def evidence_for(
    finding: Finding,
    assessment: Assessment,
    run_id: str,
) -> list[EvidenceRecord]:
    """Scanner observations + the model proposal, as validator input."""
    now = datetime.now(UTC)
    records: list[EvidenceRecord] = []
    for obs in finding.observations:
        loc = f"{obs.location.file_path}:{obs.location.line_start}" if obs.location else ""
        records.append(
            EvidenceRecord(
                evidence_id=f"ev-{finding.finding_id}-{obs.observation_id}",
                finding_id=finding.finding_id,
                kind=EvidenceKind.STATIC,
                strength=EvidenceStrength.MODERATE,
                source_description=f"{obs.tool.value} rule {obs.rule_id} at {loc}".strip(),
                source_location=loc or None,
                tool=obs.tool.value,
                created_at=now,
            )
        )
    verdict = (assessment.proposed_status or "").lower()
    conf = max(0.0, min(1.0, assessment.confidence))
    if verdict in {"confirmed", "true_positive", "true-positive", "exploitable"}:
        strength = EvidenceStrength.STRONG if conf >= 0.8 else EvidenceStrength.MODERATE
        desc = f"model verdict '{verdict}' (confidence {conf:.2f})"
    elif verdict in {"rejected", "false_positive", "false-positive", "not_exploitable"}:
        strength = EvidenceStrength.STRONG if conf >= 0.8 else EvidenceStrength.MODERATE
        desc = (
            f"model verdict '{verdict}' (confidence {conf:.2f}) contradicts the scanner conclusion"
        )
    else:
        strength = EvidenceStrength.WEAK
        desc = f"model verdict '{verdict or 'unresolved'}' (confidence {conf:.2f})"
    records.append(
        EvidenceRecord(
            evidence_id=f"ev-{finding.finding_id}-model",
            finding_id=finding.finding_id,
            kind=EvidenceKind.MODEL,
            strength=strength,
            source_description=desc,
            tool=f"{assessment.provider_id}/{assessment.model_id}",
            created_at=now,
            metadata={"assessment_id": assessment.assessment_id},
        )
    )
    return records


def run_ai_review(
    findings: list[Finding],
    routing: Sequence[dict[str, Any]],
    *,
    snapshot_root: str | Path,
    coverage_summary: dict[str, Any] | None = None,
    profile_id: str | None,
    model: str | None = None,
    max_findings: int = 10,
    budget: BudgetManager | None = None,
) -> dict[str, Any]:
    """Investigate bounded targets with the model, validate, apply statuses.

    Returns a JSON-safe report with assessments, decisions, per-finding
    outcomes, and provider usage. Never raises for provider problems:
    failures degrade to ``unresolved`` assessments and ``skipped`` stages.
    """
    report: dict[str, Any] = {
        "enabled": False,
        "stage": "targeted_deep_analysis",
        "status": "skipped",
        "detail": "",
        "targets": [],
        "assessments": [],
        "decisions": [],
        "usage": {},
        "model": model or "",
        "provider": profile_id or "",
    }
    if not profile_id:
        report["detail"] = "no provider profile configured (deterministic mode)"
        return report
    targets = pick_review_targets(findings, routing, max_findings)
    if not targets:
        report["detail"] = "no findings routed to deep analysis"
        return report
    try:
        loop, client, profile, own_budget = build_review_agent(
            profile_id,
            build_tool_handlers(snapshot_root, findings, coverage_summary),
            model,
            budget,
        )
    except (FileNotFoundError, CredentialError, ProviderError, BudgetExhausted) as exc:
        report["detail"] = f"provider unavailable: {type(exc).__name__}"
        return report

    report["enabled"] = True
    report["provider"] = profile.id
    report["model"] = loop.model_id
    validator = IndependentValidator()
    by_id = {f.finding_id: f for f in findings}
    failures = 0
    for finding in targets:
        context = {"policy": {}, "source_index": {"snapshot": str(snapshot_root)}}
        assessment = loop.investigate(finding, context)
        _, _, _, explicit = parse_verdict_text(assessment.rationale)
        if not explicit:
            # Tool-incapable model (reasoning-only gateway, empty or
            # tool-less reply): one bounded single-shot verdict with
            # embedded evidence instead of another multi-turn loop.
            single = single_shot_verdict(client, finding, str(snapshot_root), profile, model)
            if single is not None:
                assessment = single
        records = evidence_for(finding, assessment, finding.run_id)
        decision = validator.validate(finding.finding_id, finding.status, assessment, records)
        assessment.validation_outcome = decision.outcome
        assessment.validation_decision_id = decision.decision_id
        target = by_id[finding.finding_id]
        target.status = decision.new_status
        report["targets"].append(finding.finding_id)
        report["assessments"].append(json.loads(assessment.model_dump_json()))
        report["decisions"].append(json.loads(decision.model_dump_json()))
        if decision.new_status == FindingStatus.UNRESOLVED:
            failures += 1
    report["usage"] = own_budget.summary()
    report["status"] = "completed" if not failures else "partial"
    report["detail"] = (
        f"{len(targets)} investigated, "
        f"{sum(1 for d in report['decisions'] if d['new_status'] == 'confirmed')} confirmed, "
        f"{sum(1 for d in report['decisions'] if d['new_status'] == 'rejected')} rejected, "
        f"{failures} unresolved"
    )
    return report
