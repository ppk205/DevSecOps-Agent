"""Fake scanner adapter for platform tests (no real tool required).

Returns a canned ScannerResult so the job lifecycle can be exercised
end-to-end without Semgrep/SpotBugs installed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..contracts import (
    CWECategory,
    LanguageKind,
    Observation,
    ScanSpecification,
    ScannerResult,
    Severity,
    SourceCoordinate,
    ToolName,
    ToolVersionRecord,
)
from .base import ScannerAdapter


class FakeScannerAdapter(ScannerAdapter):
    """Deterministic canned results."""
    name = "fake"

    def is_available(self) -> bool:
        return True

    def version(self) -> str | None:
        return "1.0.0-fake"

    def run(self, spec: ScanSpecification, snapshot_path: Path) -> ScannerResult:
        obs = Observation(
            rule_id="fake/sql-injection",
            severity=Severity.HIGH,
            cwe=CWECategory.SQL_INJECTION,
            source=ToolName.SEMGREP,
            location=SourceCoordinate(
                file_path="src/main/java/com/jva/bookstore/dao/UserDAO.java",
                language=LanguageKind.JAVA,
                line_start=42,
                symbol="login",
            ),
            message="Canned SQL-injection observation from the fake adapter.",
        )
        return ScannerResult(
            tool=ToolName.SEMGREP,
            tool_version=ToolVersionRecord(tool=ToolName.SEMGREP, version="1.0.0-fake"),
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            observations=[obs],
            raw_output_paths=[],
            exit_code=0,
            success=True,
        )
