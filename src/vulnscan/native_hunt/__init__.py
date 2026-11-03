"""Native regex hunt rule packs.

Regex-based ports of ``src/vulnscan/scanners/rules/*.yml`` for environments
where Semgrep is unavailable. Each ``rules/<language>.json`` file holds
``{"language": ..., "rules": [...]}``; every rule carries an ``attack``
category and a non-empty ``patterns`` list of Python ``re`` regexes.
"""

from __future__ import annotations

from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent / "rules"
