"""End-to-end scan pipeline.

Architecture (authoritative order, matching the approved design):

```text
Deterministic evidence
        ↓
Laya batch routing        (advisory, skippable)
        ↓
Targeted deep analysis   (optional AI; absent in deterministic mode)
        ↓
Independent validation
        ↓
Human decision support   (report + dashboard)
```

Guarantees enforced here:

* scanner failures are recorded, never raised
* Laya is advisory: it cannot write a finding status
* ``IndependentValidator`` is the only writer of final status
* the baseline completes even when Laya, AI providers, or Docker are missing
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnscan.contracts import (
    ExportFormat,
    Finding,
    RunStatus,
    ScannerResult,
    ScanSpecification,
)
from vulnscan.normalization.dedup import deduplicate_findings
from vulnscan.normalization.grouping import group_findings
from vulnscan.normalization.normalizer import normalize_result

from ..core.native import compute
from ..decisions.batching import DecisionCache, triage_many_batched
from ..decisions.config import LayaConfig
from ..decisions.laya import LayaDecisionBackend
from ..decisions.router import DecisionRouter
from ..decisions.triage import build_triage_questions
from ..reporting.reporter import ReportGenerator
from ..scanners.base import AdapterRegistry

_LOGGER = logging.getLogger(__name__)

STAGE_EVIDENCE = "deterministic_evidence"
STAGE_ROUTING = "laya_batch_routing"
STAGE_DEEP_ANALYSIS = "targeted_deep_analysis"
STAGE_VALIDATION = "independent_validation"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _evidence_status(results: Sequence[ScannerResult], errors: Sequence[str]) -> str:
    """Honest evidence-stage status: never call a failed scanner stage 'completed'.

    * no scanner ran at all -> failed
    * every scanner failed or was skipped, and nothing was produced -> failed
    * some scanners worked but others reported errors -> partial
    * every enabled scanner completed cleanly -> completed
    """
    if not results:
        return "failed"
    if not errors and all(r.status is RunStatus.COMPLETED for r in results):
        return "completed"
    if any(r.status is RunStatus.COMPLETED for r in results):
        return "partial"
    return "failed"


@dataclass
class StageRecord:
    """One pipeline stage outcome; partial is reported honestly."""

    name: str
    status: str
    detail: str = ""
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


@dataclass
class PipelineResult:
    """Everything a run produced, including honest coverage of failures."""

    run_id: str
    spec: ScanSpecification
    findings: list[Finding]
    scanner_results: list[ScannerResult]
    stages: list[StageRecord]
    coverage: dict[str, Any] = field(default_factory=dict)
    routing_payloads: list[dict[str, Any]] = field(default_factory=list)
    reports: dict[str, str] = field(default_factory=dict)

    @property
    def laya_routes(self) -> dict[str, str]:
        return {p["finding_id"]: p["route"] for p in self.routing_payloads}

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target": self.spec.target_repository_url,
            "commit": self.spec.target_commit_sha,
            "findings": len(self.findings),
            "stages": [s.as_dict() for s in self.stages],
            "scanner_results": [
                {
                    "tool": r.tool.value,
                    "status": r.status.value,
                    "errors": list(r.errors),
                }
                for r in self.scanner_results
            ],
            "routing": self.routing_payloads,
            "reports": self.reports,
        }


class ScanPipeline:
    """Deterministic-first pipeline with optional Laya and AI stages."""

    def __init__(
        self,
        spec: ScanSpecification,
        *,
        registry: AdapterRegistry | None = None,
        laya_config: LayaConfig | None = None,
        output_dir: str | Path | None = None,
        agent: Any = None,
    ) -> None:
        # Pydantic already validated the spec at construction time.
        self.spec = spec
        self.registry = registry or AdapterRegistry.default()
        self.laya_config = laya_config or LayaConfig()
        self.output_dir = Path(output_dir) if output_dir else None
        self.agent = agent
        self.cache = DecisionCache()

    # ------------------------------------------------------------------ #
    # Stage 1 — deterministic evidence
    # ------------------------------------------------------------------ #
    def run_scanners(self) -> tuple[list[ScannerResult], StageRecord]:
        """Execute enabled scanners. A missing tool is data, not an exception."""
        workdir = self.spec.repository_checkout_path or "."
        results: list[ScannerResult] = []
        errors: list[str] = []
        for cfg in self.spec.tools:
            if not cfg.enabled:
                continue
            adapter = self.registry.get(cfg.tool)
            if adapter is None:
                errors.append(f"{cfg.tool.value}: no adapter registered")
                continue
            try:
                result = adapter.run(self.spec, workdir=workdir)
            except Exception as exc:  # adapter boundary: record, never propagate
                _LOGGER.exception("scanner %s raised", cfg.tool.value)
                errors.append(f"{cfg.tool.value}: adapter error {type(exc).__name__}: {exc}")
                continue
            results.append(result)
            errors.extend(f"{cfg.tool.value}: {e}" for e in result.errors)

        return results, StageRecord(
            name=STAGE_EVIDENCE,
            status=_evidence_status(results, errors),
            detail="; ".join(errors),
            finished_at=_utcnow(),
        )

    @staticmethod
    def build_findings(results: Sequence[ScannerResult], run_id: str) -> list[Finding]:
        """Normalize, group, and dedupe observations into human-visible findings."""
        observations = []
        for result in results:
            observations.extend(normalize_result(result))
        native = compute(
            "group",
            {"observations": [o.model_dump(mode="json") for o in observations], "run_id": run_id},
        )
        grouped = (
            [Finding.model_validate(f) for f in native]
            if native is not None
            else group_findings(observations, run_id=run_id)
        )
        return deduplicate_findings(grouped)

    # ------------------------------------------------------------------ #
    # Stage 2 — Laya advisory batch routing
    # ------------------------------------------------------------------ #
    def run_routing(self, findings: Sequence[Finding]) -> tuple[list[dict[str, Any]], StageRecord]:
        """Advisory routing only. Never mutates finding status."""
        if not self.laya_config.enabled:
            return [], StageRecord(
                name=STAGE_ROUTING,
                status="skipped",
                detail="laya disabled (baseline mode)",
                finished_at=_utcnow(),
            )
        if not findings:
            return [], StageRecord(
                name=STAGE_ROUTING,
                status="skipped",
                detail="no findings to route",
                finished_at=_utcnow(),
            )

        backend = LayaDecisionBackend(
            model_id=self.laya_config.model_id,
            model_revision=self.laya_config.revision,
            device=self.laya_config.device,
            max_input_tokens=self.laya_config.max_input_tokens,
            timeout_seconds=self.laya_config.timeout_seconds,
        )
        questions = build_triage_questions()
        try:
            outcomes = triage_many_batched(
                list(findings),
                backend,
                questions,
                router=DecisionRouter(
                    high_confidence_threshold=self.laya_config.high_confidence_threshold,
                    review_threshold=self.laya_config.review_threshold,
                ),
                batch_size=self.laya_config.batch_size,
                cache=self.cache if self.laya_config.cache_enabled else None,
                max_input_tokens=self.laya_config.max_input_tokens,
            )
        except Exception as exc:  # routing is an optimisation, never a gate
            _LOGGER.exception("laya routing failed")
            return [], StageRecord(
                name=STAGE_ROUTING,
                status="failed",
                detail=f"{type(exc).__name__}: {exc}",
                finished_at=_utcnow(),
            )

        payloads = [o.as_artifact_payload() for o in outcomes]
        unavailable = [p for p in payloads if p["decision_status"] != "completed"]
        status = "completed" if not unavailable else "partial"
        detail = (
            f"{len(payloads)} routed, {len(unavailable)} unavailable"
            if unavailable
            else f"{len(payloads)} routed"
        )
        return payloads, StageRecord(
            name=STAGE_ROUTING, status=status, detail=detail, finished_at=_utcnow()
        )

    # ------------------------------------------------------------------ #
    # Stage 3 — targeted deep analysis (optional)
    # ------------------------------------------------------------------ #
    def run_deep_analysis(
        self, findings: Sequence[Finding], routing: Sequence[dict[str, Any]]
    ) -> StageRecord:
        """Target only the findings Laya routed to deep analysis, when an agent exists."""
        if self.agent is None:
            return StageRecord(
                name=STAGE_DEEP_ANALYSIS,
                status="skipped",
                detail="no AI agent configured (deterministic mode)",
                finished_at=_utcnow(),
            )
        targets = [
            p["finding_id"]
            for p in routing
            if p["route"]
            in {"cross_file_analysis", "jsp_context_analysis", "authorization_analysis"}
        ]
        if not targets:
            return StageRecord(
                name=STAGE_DEEP_ANALYSIS,
                status="skipped",
                detail="no findings routed to deep analysis",
                finished_at=_utcnow(),
            )
        return StageRecord(
            name=STAGE_DEEP_ANALYSIS,
            status="unavailable",
            detail="targeted deep analysis is not implemented",
            finished_at=_utcnow(),
        )

    # ------------------------------------------------------------------ #
    # Orchestration
    # ------------------------------------------------------------------ #
    def run(self) -> PipelineResult:
        """Execute the full pipeline. Deterministic stages always complete."""
        run_id = self.spec.run_id or f"run-{int(_utcnow().timestamp())}"

        results, evidence_stage = self.run_scanners()
        findings = self.build_findings(results, run_id)
        routing, routing_stage = self.run_routing(findings)
        deep_stage = self.run_deep_analysis(findings, routing)

        # Validation is mechanical: with no assessment/verification input every
        # finding stays UNPROCESSED and final status remains validator-owned.
        validation_stage = StageRecord(
            name=STAGE_VALIDATION,
            status="skipped",
            detail=(
                f"{len(findings)} findings retain validator-owned status "
                "(no assessment/verification evidence supplied)"
            ),
            finished_at=_utcnow(),
        )

        reports: dict[str, str] = {}
        if self.output_dir is not None:
            generator = ReportGenerator(run_id, findings, routing_payloads=routing)
            for fmt in ExportFormat:
                export = generator.export(fmt, self.output_dir, generated_by="pipeline")
                reports[fmt.value] = str(export.artifact_ref.path)

        return PipelineResult(
            run_id=run_id,
            spec=self.spec,
            findings=findings,
            scanner_results=results,
            stages=[evidence_stage, routing_stage, deep_stage, validation_stage],
            routing_payloads=routing,
            reports=reports,
        )
