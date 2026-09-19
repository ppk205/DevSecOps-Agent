"""Scanner adapter interface and registry.

An adapter is the *only* module that understands a vendor's native output
shape.  Everything downstream consumes :class:`ScannerResult` envelopes.

Design rules
------------
* Missing binaries are a documented condition, never an exception.
  ``AdapterCapability`` reports presence; adapters return a result whose
  ``status`` is ``failed`` with the reason in ``errors`` (or ``skipped`` when
  the scan spec disables the tool).
* Parsing is pure: ``parse`` takes already-fetched text so tests drive
  fixtures through it without a subprocess.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Sequence

from vulnscan.contracts import (
    CoverageRecord,
    RunStatus,
    ScanSpecification,
    ScannerResult,
    ToolName,
)

from .platform import which
from .process import CommandResult, run_command

ADAPTER_VERSION = "0.1.0"
"""Bumped whenever an adapter's normalization logic changes output meaning."""


@dataclass(frozen=True)
class AdapterCapability:
    """What an adapter declared about its tool and environment."""

    tool: ToolName
    binary: str | None = None
    version: str | None = None
    available: bool = False
    reason: str | None = None

    def unavailable_message(self) -> str:
        """Stable human-readable reason for the unavailability."""
        if self.available:
            return ""
        if self.reason:
            return f"{self.binary or self.tool.value}: {self.reason}"
        return f"{self.binary or self.tool.value}: binary not found on PATH"


class ScannerAdapter(abc.ABC):
    """Vendor-specific scanner adapter."""

    #: Tool this adapter binds to.
    tool: ToolName
    #: Executable name looked up on PATH.
    binary_name: str
    #: Adapter implementation version (see :data:`ADAPTER_VERSION`).
    adapter_version: str = ADAPTER_VERSION
    #: Default per-invocation timeout in seconds.
    default_timeout: float = 600.0

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    @abc.abstractmethod
    def capabilities(self) -> AdapterCapability:
        """Probe the environment for the tool binary and its version."""

    @abc.abstractmethod
    def run(self, spec: ScanSpecification, *, workdir: str) -> ScannerResult:
        """Execute the tool for *spec* and return a normalized result.

        Never raises for environmental problems (missing binary, timeout,
        non-zero exit): those are recorded in the returned envelope.
        """

    # ------------------------------------------------------------------ #
    # Shared helpers
    # ------------------------------------------------------------------ #

    def _tool_config(self, spec: ScanSpecification) -> Any:
        """Return this tool's :class:`ToolConfig`, or ``None`` when absent."""
        for cfg in spec.tools:
            if cfg.tool == self.tool:
                return cfg
        return None

    def _skipped_result(
        self, spec: ScanSpecification, started_at: Any, reason: str
    ) -> ScannerResult:
        """Build a ``skipped`` envelope for a disabled/absent tool."""
        return ScannerResult(
            run_id=spec.run_id,
            tool=self.tool,
            tool_version="unknown",
            adapter_version=self.adapter_version,
            status=RunStatus.SKIPPED if "disabled" in reason else RunStatus.FAILED,
            started_at=started_at,
            finished_at=started_at,
            errors=[reason],
        )

    def _invoke(
        self,
        argv: Sequence[str],
        *,
        cwd: str,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        """Run the tool binary, translating a missing binary into a result."""
        if which(str(argv[0])) is None:
            return CommandResult(
                returncode=127,
                stderr=f"binary not found: {argv[0]}",
                command=tuple(str(a) for a in argv),
            )
        return run_command(
            argv,
            cwd=cwd,
            timeout=timeout if timeout is not None else self.default_timeout,
            env=env,
        )

    def _fatal(
        self,
        spec: ScanSpecification,
        started_at: Any,
        finished_at: Any,
        result: CommandResult,
        *,
        note: str,
    ) -> ScannerResult:
        """Envelope for a tool invocation that could not produce output."""
        detail = note
        if result.timed_out:
            detail = f"{note}; timed out after {result.duration_ms} ms"
        elif result.returncode not in (0, 1):
            detail = (
                f"{note}; exit code {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()[:400]}"
            )
        return ScannerResult(
            run_id=spec.run_id,
            tool=self.tool,
            tool_version="unknown",
            adapter_version=self.adapter_version,
            status=RunStatus.FAILED,
            started_at=started_at,
            finished_at=finished_at,
            errors=[detail],
            warnings=[] if result.succeeded or result.timed_out else [note],
            duration_ms=result.duration_ms,
        )


@dataclass
class AdapterRegistry:
    """Lookup of tool -> adapter, created once per process."""

    adapters: dict[str, ScannerAdapter] = field(default_factory=dict)

    @classmethod
    def default(cls) -> "AdapterRegistry":
        """Build the registry with every adapter shipped in this package."""
        from .codeql_adapter import CodeQLAdapter
        from .dependency_check_adapter import DependencyCheckAdapter
        from .gitleaks_adapter import GitleaksAdapter
        from .semgrep_adapter import SemgrepAdapter
        from .spotbugs_adapter import SpotBugsAdapter

        registry = cls()
        for adapter in (
            SemgrepAdapter(),
            SpotBugsAdapter(),
            DependencyCheckAdapter(),
            GitleaksAdapter(),
            CodeQLAdapter(),
        ):
            registry.register(adapter)
        return registry

    def register(self, adapter: ScannerAdapter) -> None:
        """Add *adapter* under its tool name."""
        self.adapters[adapter.tool.value] = adapter

    def get(self, tool: ToolName | str) -> ScannerAdapter | None:
        """Return the adapter for *tool*, or ``None`` when unregistered."""
        return self.adapters.get(tool.value if isinstance(tool, ToolName) else tool)

    def __contains__(self, tool: ToolName | str) -> bool:
        return self.get(tool) is not None

    def __len__(self) -> int:
        return len(self.adapters)


__all__ = [
    "ADAPTER_VERSION",
    "AdapterCapability",
    "AdapterRegistry",
    "ScannerAdapter",
]
