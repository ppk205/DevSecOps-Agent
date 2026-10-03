"""A scanner reporting internal errors must fail the gate, not pass it clean.

Semgrep exits 0 even when a ruleset fails to load, so a broken configuration is
indistinguishable from a clean repository at the exit-code level. If these errors
stay out of the gate, the tool reports "no vulnerabilities" on a repo it never
actually scanned.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    CWECategory,
    Observation,
    RunStatus,
    ScannerResult,
    Severity,
    SourceCoordinate,
    ToolName,
)
from vulnscan.core.config import ScanConfig
from vulnscan.core.scan_service import ScanService
from vulnscan.scanners.base import AdapterCapability, AdapterRegistry, ScannerAdapter

from tests.platform.test_scan_service import checkout  # noqa: F401


class BrokenRulesetAdapter(ScannerAdapter):
    """Completes with full coverage but the ruleset never loaded."""

    tool = ToolName.SEMGREP
    binary_name = "fixture"

    def capabilities(self):
        return AdapterCapability(self.tool, available=True)

    def run(self, spec, *, workdir):
        now = datetime.now(UTC)
        return ScannerResult(
            run_id=spec.run_id,
            tool=self.tool,
            tool_version="test",
            adapter_version="test",
            status=RunStatus.COMPLETED,
            started_at=now,
            finished_at=now,
            observations=[],
            coverage_records=[
                CoverageRecord(
                    run_id=spec.run_id,
                    tool=self.tool,
                    tool_version="test",
                    source_snapshot=spec.target_commit_sha,
                    unit_path="Example.java",
                    eligible=True,
                    status=CoverageUnitStatus.ANALYZED,
                    analyzed_at=now,
                )
            ],
            errors=["config error: ruleset p/java failed to load"],
        )


@pytest.fixture
def broken_service(tmp_path):
    registry = AdapterRegistry()
    registry.register(BrokenRulesetAdapter())
    leaks = BrokenRulesetAdapter()
    leaks.tool = ToolName.GITLEAKS
    registry.register(leaks)
    return ScanService(str(tmp_path / "runs.db"), registry)


def test_gate_does_not_pass_when_ruleset_failed_to_load(checkout, broken_service, tmp_path):  # noqa: F811
    """A clean inventory must not hide a scanner that never actually scanned."""
    result = broken_service.run(str(checkout), ScanConfig(output_dir=str(tmp_path / "reports")))
    assert result["exit_code"] != 0, (
        "gate passed despite every scanner reporting a failed ruleset"
    )
    assert any("failed to load" in error for error in result["errors"]), result["errors"]
