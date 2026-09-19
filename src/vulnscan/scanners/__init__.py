"""Scanner adapters for the DevSecOps-Agent pipeline.

Every adapter implements :class:`vulnscan.scanners.base.ScannerAdapter` and
returns a :class:`vulnscan.contracts.ScannerResult` envelope.  Adapters are the
*only* place vendor-specific output shapes are understood: downstream stages
see normalized observations only.

Missing binaries are a documented condition, never an exception: the adapter
records the unavailability in ``errors`` and returns a result whose status is
``failed`` (or ``skipped`` when the tool is disabled in the scan spec).
"""

from __future__ import annotations

from .base import AdapterCapability, AdapterRegistry, ScannerAdapter
from .codeql_adapter import CodeQLAdapter
from .dependency_check_adapter import DependencyCheckAdapter
from .gitleaks_adapter import GitleaksAdapter
from .semgrep_adapter import SemgrepAdapter
from .spotbugs_adapter import SpotBugsAdapter

__all__ = [
    "AdapterCapability",
    "AdapterRegistry",
    "CodeQLAdapter",
    "DependencyCheckAdapter",
    "GitleaksAdapter",
    "ScannerAdapter",
    "SemgrepAdapter",
    "SpotBugsAdapter",
]
