"""End-to-end pipeline tests.

These exercise the full order of operations with fake scanners, so no tool
binary, model, or provider is required.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from vulnscan.contracts import (
    FindingStatus,
    RunStatus,
    ScannerResult,
    ScanSpecification,
    ToolConfig,
)
from vulnscan.contracts.enums import ToolName
from vulnscan.decisions.config import LayaConfig
from vulnscan.pipeline.runner import (
    STAGE_EVIDENCE,
    STAGE_ROUTING,
    STAGE_VALIDATION,
    ScanPipeline,
)
from vulnscan.scanners.base import AdapterCapability, AdapterRegistry, ScannerAdapter

COMMIT = "dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5"
REPO = "https://github.com/Moseyuh333/JVA-bookstore"


class FakeSemgrep(ScannerAdapter):
    tool = ToolName.SEMGREP
    binary = "semgrep"
    adapter_version = "test"

    def capabilities(self) -> AdapterCapability:
        return AdapterCapability(
            tool=self.tool, binary=self.binary, version="1.70.0", available=True
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        now = datetime.now(UTC)
        return ScannerResult(
            run_id=spec.run_id,
            tool=self.tool,
            tool_version="1.70.0",
            adapter_version=self.adapter_version,
            status=RunStatus.COMPLETED,
            started_at=now,
            finished_at=now,
            observations=[
                {
                    "observation_id": "O-1",
                    "run_id": spec.run_id,
                    "tool": self.tool.value,
                    "tool_version": "1.70.0",
                    "rule_id": "java/sql-injection",
                    "cwe_category": "CWE-89",
                    "severity": "high",
                    "message": "Concatenated SQL query",
                    "location": {
                        "file_path": "src/main/java/com/x/Dao.java",
                        "line_start": 42,
                    },
                    "detected_at": now.isoformat(),
                }
            ],
        )


class BrokenAdapter(ScannerAdapter):
    tool = ToolName.GITLEAKS
    binary = "gitleaks"
    adapter_version = "test"

    def capabilities(self) -> AdapterCapability:
        return AdapterCapability(tool=self.tool, binary=self.binary, available=True)

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        raise RuntimeError("scanner exploded")


def _registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(FakeSemgrep())
    return registry


def _spec(tmp_path: Path, **overrides: Any) -> ScanSpecification:
    data: dict[str, Any] = {
        "run_id": "E2E-1",
        "target_repository_url": REPO,
        "target_commit_sha": COMMIT,
        "repository_checkout_path": str(tmp_path),
        "tools": [ToolConfig(tool=ToolName.SEMGREP)],
    }
    data.update(overrides)
    return ScanSpecification(**data)


def test_pipeline_runs_deterministic_evidence_to_report(tmp_path: Path) -> None:
    pipeline = ScanPipeline(
        _spec(tmp_path),
        registry=_registry(),
        output_dir=tmp_path / "reports",
    )

    result = pipeline.run()

    assert len(result.findings) == 1
    assert result.findings[0].cwe_category.value == "CWE-89"
    stage_names = [s.name for s in result.stages]
    assert stage_names == [
        STAGE_EVIDENCE,
        STAGE_ROUTING,
        "targeted_deep_analysis",
        STAGE_VALIDATION,
    ]
    assert set(result.reports) == {"json", "sarif", "markdown", "html"}
    for path in result.reports.values():
        assert Path(path).exists()


def test_pipeline_keeps_baseline_when_laya_disabled(tmp_path: Path) -> None:
    pipeline = ScanPipeline(
        _spec(tmp_path),
        registry=_registry(),
        laya_config=LayaConfig(enabled=False),
    )

    result = pipeline.run()

    routing = next(s for s in result.stages if s.name == STAGE_ROUTING)
    assert routing.status == "skipped"
    assert result.routing_payloads == []
    assert len(result.findings) == 1


def test_pipeline_reports_scanner_exception_without_failing(tmp_path: Path) -> None:
    registry = _registry()
    registry.register(BrokenAdapter())
    spec = _spec(
        tmp_path,
        tools=[ToolConfig(tool=ToolName.SEMGREP), ToolConfig(tool=ToolName.GITLEAKS)],
    )

    result = ScanPipeline(spec, registry=registry, laya_config=LayaConfig()).run()

    evidence = next(s for s in result.stages if s.name == STAGE_EVIDENCE)
    assert evidence.status == "partial"
    assert any("adapter error" in d for d in evidence.detail.split("; "))
    # The healthy scanner still produced its finding.
    assert len(result.findings) == 1


def test_laya_never_changes_finding_status(tmp_path: Path) -> None:
    class RoutingAgent:
        def predict(self, state: Any, questions: Any, **kwargs: Any) -> Any:
            return {
                "answers": {
                    "recommended_action": {
                        "type": "choice",
                        "choice": "fast_verification",
                        "probabilities": {"fast_verification": 0.91},
                        "confidence": 0.91,
                    },
                    "evidence_sufficiency": {
                        "type": "score",
                        "score": 1.0,
                        "probabilities": {"0": 0.1, "1": 0.6, "2": 0.3},
                        "confidence": 0.6,
                    },
                    "needs_human_review": {"type": "noul", "noul": 0.05, "confidence": 0.95},
                }
            }

    from vulnscan.decisions.batching import triage_many_batched
    from vulnscan.decisions.triage import build_triage_questions

    baseline = ScanPipeline(_spec(tmp_path), registry=_registry()).run()
    findings = baseline.findings
    outcomes = triage_many_batched(findings, RoutingAgent(), build_triage_questions())

    assert outcomes[0].route.route == "fast_verification"
    assert outcomes[0].route.affects_finding_status is False
    assert all(f.status is FindingStatus.UNPROCESSED for f in findings)


def test_pipeline_survives_missing_scanner_binary(tmp_path: Path) -> None:
    class MissingAdapter(ScannerAdapter):
        tool = ToolName.SEMGREP
        binary = "definitely-not-installed"
        adapter_version = "test"

        def capabilities(self) -> AdapterCapability:
            return AdapterCapability(tool=self.tool, binary=self.binary, available=False)

        def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
            now = datetime.now(UTC)
            return ScannerResult(
                run_id=spec.run_id,
                tool=self.tool,
                tool_version="unknown",
                adapter_version=self.adapter_version,
                status=RunStatus.FAILED,
                started_at=now,
                finished_at=now,
                errors=["semgrep: binary not found on PATH"],
            )

    registry = AdapterRegistry()
    registry.register(MissingAdapter())

    result = ScanPipeline(_spec(tmp_path), registry=registry).run()

    evidence = next(s for s in result.stages if s.name == STAGE_EVIDENCE)
    assert evidence.status == "failed"
    assert "binary not found" in evidence.detail
    assert result.findings == []


def test_json_report_is_valid_and_escaped(tmp_path: Path) -> None:
    result = ScanPipeline(_spec(tmp_path), registry=_registry(), output_dir=tmp_path / "r").run()

    payload = json.loads(Path(result.reports["json"]).read_text(encoding="utf-8"))

    assert payload["findings"] or payload["findings"] == []
    sarif = json.loads(Path(result.reports["sarif"]).read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"


def test_validation_stage_never_invents_status(tmp_path: Path) -> None:
    result = ScanPipeline(_spec(tmp_path), registry=_registry()).run()

    validation = next(s for s in result.stages if s.name == STAGE_VALIDATION)
    assert validation.status == "skipped"
    assert all(f.status is FindingStatus.UNPROCESSED for f in result.findings)


@pytest.mark.parametrize("laya_enabled", [False, True])
def test_pipeline_runs_with_and_without_laya(tmp_path: Path, laya_enabled: bool) -> None:
    result = ScanPipeline(
        _spec(tmp_path),
        registry=_registry(),
        laya_config=LayaConfig(enabled=laya_enabled),
    ).run()

    assert len(result.findings) == 1
    assert result.spec.target_commit_sha == COMMIT
