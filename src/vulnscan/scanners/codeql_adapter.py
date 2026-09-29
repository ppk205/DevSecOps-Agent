"""CodeQL adapter (ACC-01 experimental).

Reports unavailable when the CodeQL CLI is not installed. Extraction mode,
query versions, and limitations are recorded for every invocation. No
complete cross-file or JSP coverage claim is ever made.
"""

from __future__ import annotations

from datetime import UTC, datetime

from vulnscan.contracts import (
    RunStatus,
    ScannerResult,
    ScanSpecification,
    ToolName,
)

from .base import AdapterCapability, ScannerAdapter
from .platform import which
from .process import run_command

ADAPTER_VERSION = "0.2.0-experimental"


class CodeQLAdapter(ScannerAdapter):
    """Experimental CodeQL adapter for cross-file analysis (ACC-01)."""

    tool = ToolName.CODEQL
    binary_name = "codeql"

    def capabilities(self) -> AdapterCapability:
        resolved = which(self.binary_name)
        if resolved is None:
            return AdapterCapability(
                tool=self.tool,
                binary=self.binary_name,
                version=None,
                available=False,
                reason=f"{self.binary_name} not found on PATH; CodeQL remains experimental",
            )
        # Probe version.
        proc = run_command([self.binary_name, "version", "--format", "json"])
        version = proc.stdout.strip() if proc.returncode == 0 else "unknown"
        return AdapterCapability(
            tool=self.tool,
            binary=self.binary_name,
            version=version,
            available=True,
        )

    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        cap = self.capabilities()
        started = datetime.now(UTC)
        tool_cfg = self._tool_config(spec)

        if tool_cfg and not tool_cfg.enabled:
            return self._skipped_result(spec, started, "CodeQL disabled in scan spec")

        if not cap.available:
            return self._skipped_result(spec, started, cap.unavailable_message())

        # CodeQL database creation + query run would go here.
        # For now, return a documented incomplete result.
        return ScannerResult(
            run_id=spec.run_id or "unassigned",
            tool=ToolName.CODEQL,
            tool_version=cap.version or "unknown",
            adapter_version=ADAPTER_VERSION,
            status=RunStatus.FAILED,
            started_at=started,
            finished_at=datetime.now(UTC),
            observations=[],
            coverage_records=[],
            errors=[
                "CodeQL integration is experimental (ACC-01): cross-file query execution is a future milestone. No complete cross-file or JSP coverage is claimed."
            ],
            warnings=["CodeQL results are not yet merged into the baseline combination"],
        )
