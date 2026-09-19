"""Shared data contracts for the DevSecOps-Agent pipeline.

Import models from this package root rather than from individual files:

    from vulnscan.contracts import Finding, RunStatus, ScanSpecification

Contract changes are coordinator-owned: after T00, updates go through the
coordinator, who updates consumers and fixtures together.
"""

from __future__ import annotations

from .__all__ import *
from .__all__ import __all__

# Re-bind the exported list under this package's own name.
__all__ = list(__all__)
