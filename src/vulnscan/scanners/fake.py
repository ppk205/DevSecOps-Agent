"""Adapter scanner giả lập phục vụ kiểm thử nền tảng (không yêu cầu công cụ thực tế).

Trả về một ScannerResult dựng sẵn để có thể kiểm thử toàn trình vòng đời của job
mà không cần cài đặt Semgrep/SpotBugs.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..contracts import (
    CWECategory,
    LanguageKind,
    Observation,
    RunStatus,
    ScannerResult,
    ScanSpecification,
    Severity,
    SourceCoordinate,
    ToolName,
)
from .base import AdapterCapability, ScannerAdapter


class FakeScannerAdapter(ScannerAdapter):
    """Các kết quả dựng sẵn có tính tất định."""

    tool = ToolName.SEMGREP
    binary_name = "fake-scanner"

    def capabilities(self) -> AdapterCapability:
        return AdapterCapability(
            tool=self.tool,
            binary=self.binary_name,
            version="1.0.0-fake",
            available=True,
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        started = datetime.now(UTC)
        obs = Observation(
            observation_id="fake-obs-1",
            detected_at=started,
            run_id=spec.run_id or "fake-run",
            tool=ToolName.SEMGREP,
            tool_version="1.0.0-fake",
            rule_id="fake/sql-injection",
            cwe_category=CWECategory.SQL_INJECTION,
            severity=Severity.HIGH,
            message="Canned SQL-injection observation from the fake adapter.",
            confidence=1.0,
            location=SourceCoordinate(
                file_path="src/main/java/com/jva/bookstore/dao/UserDAO.java",
                language=LanguageKind.JAVA,
                line_start=42,
                symbol="login",
            ),
        )
        return ScannerResult(
            run_id=spec.run_id or "fake-run",
            tool=ToolName.SEMGREP,
            tool_version="1.0.0-fake",
            adapter_version=self.adapter_version,
            status=RunStatus.COMPLETED,
            started_at=started,
            finished_at=datetime.now(UTC),
            observations=[obs],
        )
