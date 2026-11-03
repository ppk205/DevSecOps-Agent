"""Native regex taint-hunt engine: taint flow without Semgrep or a model.

Rule packs live in ``rules/<family>.json`` in two shapes: the port shape
(``{"language": ..., "rules": [...]}`` with sink ``patterns`` ported from
``src/vulnscan/scanners/rules/*.yml``, given family default
sources/sanitizers) and the taint shape (a JSON list with
``sources``/``sinks``/``sanitizers``). See
:mod:`vulnscan.native_hunt.taint`.
"""

from __future__ import annotations

from .engine import (
    FAMILY_EXTENSIONS,
    MAX_FILE_BYTES,
    MAX_ITERATIONS,
    Finding,
    SnapshotResult,
    scan_file,
    scan_snapshot,
)
from .taint import RULES_DIR, Rule, Sanitizer, load_rules

__all__ = [
    "FAMILY_EXTENSIONS",
    "MAX_FILE_BYTES",
    "MAX_ITERATIONS",
    "RULES_DIR",
    "Finding",
    "Rule",
    "Sanitizer",
    "SnapshotResult",
    "load_rules",
    "scan_file",
    "scan_snapshot",
]
