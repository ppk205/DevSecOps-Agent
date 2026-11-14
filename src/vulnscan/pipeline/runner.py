"""Pipeline quét toàn trình (end-to-end).

Kiến trúc (thứ tự chuẩn hóa, khớp với thiết kế đã phê duyệt):

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

Các bảo đảm được thực thi tại đây:

* các lỗi scanner được ghi nhận, không bao giờ ném ngoại lệ
* Laya chỉ mang tính tư vấn: nó không thể ghi trạng thái finding
* ``IndependentValidator`` là bên duy nhất có quyền ghi trạng thái cuối cùng
* baseline luôn hoàn thành ngay cả khi thiếu Laya, các nhà cung cấp AI, hoặc Docker
"""

from __future__ import annotations

import logging
import os
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
    """Trạng thái trung thực của giai đoạn bằng chứng: không bao giờ gọi giai đoạn scanner thất bại là 'completed'.

    * không có scanner nào chạy -> failed
    * mọi scanner đều thất bại hoặc bị bỏ qua, và không có gì được tạo ra -> failed
    * một số scanner hoạt động nhưng số khác báo lỗi -> partial
    * mọi scanner được kích hoạt đều hoàn thành thành công -> completed
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
    """Kết quả của một giai đoạn trong pipeline; partial được báo cáo một cách trung thực."""

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
    """Toàn bộ kết quả một lượt chạy tạo ra, bao gồm thông tin độ bao phủ trung thực về các lỗi."""

    run_id: str
    spec: ScanSpecification
    findings: list[Finding]
    scanner_results: list[ScannerResult]
    stages: list[StageRecord]
    coverage: dict[str, Any] = field(default_factory=dict)
    routing_payloads: list[dict[str, Any]] = field(default_factory=list)
    reports: dict[str, str] = field(default_factory=dict)
    assessments: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)

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
    """Pipeline ưu tiên tính tất định với các giai đoạn Laya và AI tùy chọn."""

    def __init__(
        self,
        spec: ScanSpecification,
        *,
        registry: AdapterRegistry | None = None,
        laya_config: LayaConfig | None = None,
        output_dir: str | Path | None = None,
        agent: Any = None,
    ) -> None:
        # Pydantic đã xác thực spec tại thời điểm khởi tạo.
        self.spec = spec
        self.registry = registry or AdapterRegistry.default()
        self.laya_config = laya_config or LayaConfig()
        self.output_dir = Path(output_dir) if output_dir else None
        self.agent = agent
        self.cache = DecisionCache()

    # ------------------------------------------------------------------ #
    # Giai đoạn 1 — bằng chứng tất định (deterministic evidence)
    # ------------------------------------------------------------------ #
    def run_scanners(self) -> tuple[list[ScannerResult], StageRecord]:
        """Thực thi các scanner được bật. Công cụ bị thiếu là dữ liệu, không phải ngoại lệ."""
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
            except Exception as exc:  # ranh giới adapter: ghi nhận, không bao giờ lan truyền ngoại lệ
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
        """Chuẩn hóa, nhóm và khử trùng lặp các observation thành các finding người dùng có thể xem được."""
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
    # Giai đoạn 2 — định tuyến theo lô mang tính tư vấn của Laya
    # ------------------------------------------------------------------ #
    def run_routing(self, findings: Sequence[Finding]) -> tuple[list[dict[str, Any]], StageRecord]:
        """Chỉ định tuyến mang tính tư vấn. Không bao giờ thay đổi trạng thái finding."""
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
            device=os.environ.get("LAYA_DEVICE", "cpu").strip().lower() or "cpu",
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
        except Exception as exc:  # định tuyến là một bước tối ưu hóa, không bao giờ là cổng chặn (gate)
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
    # Giai đoạn 3 — phân tích sâu có mục tiêu (tùy chọn)
    # ------------------------------------------------------------------ #
    def run_deep_analysis(
        self, findings: Sequence[Finding], routing: Sequence[dict[str, Any]]
    ) -> tuple[StageRecord, list[dict[str, Any]], list[dict[str, Any]]]:
        """Điều tra các finding đã được định tuyến khi có agent; không bao giờ ném ngoại lệ.

        Trả về (stage, assessments, decisions). Khi không có agent, giai đoạn này
        sẽ được bỏ qua và baseline tất định vẫn được giữ nguyên.
        """
        from vulnscan.ai.review import build_tool_handlers, evidence_for, pick_review_targets
        from vulnscan.assessment.validator import IndependentValidator

        if self.agent is None:
            return (
                StageRecord(
                    name=STAGE_DEEP_ANALYSIS,
                    status="skipped",
                    detail="no AI agent configured (deterministic mode)",
                    finished_at=_utcnow(),
                ),
                [],
                [],
            )
        targets = pick_review_targets(
            findings,
            routing,
            getattr(self.spec, "max_ai_findings", 10)
            if isinstance(getattr(self.spec, "max_ai_findings", 10), int)
            else 10,
        )
        if not targets:
            return (
                StageRecord(
                    name=STAGE_DEEP_ANALYSIS,
                    status="skipped",
                    detail="no findings routed to deep analysis",
                    finished_at=_utcnow(),
                ),
                [],
                [],
            )
        handlers = build_tool_handlers(self.spec.repository_checkout_path or ".", findings)
        if hasattr(self.agent, "tool_handlers"):
            try:
                self.agent.tool_handlers.update(handlers)
            except (AttributeError, TypeError):
                pass
        validator = IndependentValidator()
        assessments: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        failures = 0
        for finding in targets:
            try:
                assessment = self.agent.investigate(finding, {"policy": {}, "source_index": {}})
            except Exception as exc:  # noqa: BLE001 — one bad target never fails the run
                _LOGGER.warning("deep analysis failed for %s: %s", finding.finding_id, exc)
                failures += 1
                continue
            records = evidence_for(finding, assessment, finding.run_id)
            decision = validator.validate(finding.finding_id, finding.status, assessment, records)
            assessment.validation_outcome = decision.outcome
            assessment.validation_decision_id = decision.decision_id
            finding.status = decision.new_status
            assessments.append(assessment.model_dump(mode="json"))
            decisions.append(decision.model_dump(mode="json"))
        return (
            StageRecord(
                name=STAGE_DEEP_ANALYSIS,
                status="completed" if not failures else "partial",
                detail=f"{len(targets)} investigated, {failures} failed",
                finished_at=_utcnow(),
            ),
            assessments,
            decisions,
        )

    # ------------------------------------------------------------------ #
    # Điều phối (Orchestration)
    # ------------------------------------------------------------------ #
    def run(self) -> PipelineResult:
        """Thực thi toàn bộ pipeline. Các giai đoạn tất định luôn luôn hoàn thành."""
        run_id = self.spec.run_id or f"run-{int(_utcnow().timestamp())}"

        results, evidence_stage = self.run_scanners()
        findings = self.build_findings(results, run_id)
        routing, routing_stage = self.run_routing(findings)
        deep_stage, assessments, decisions = self.run_deep_analysis(findings, routing)

        # Việc xác thực diễn ra hoàn toàn cơ học: nếu không có đầu vào assessment/verification thì mọi
        # finding vẫn ở trạng thái UNPROCESSED và trạng thái cuối cùng do validator quyết định.
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
            assessments=assessments,
            decisions=decisions,
        )
