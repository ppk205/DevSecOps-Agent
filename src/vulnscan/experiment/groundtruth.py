"""Ground truth for the experiment and the matching rules that score rows.

A row is one finding reported by one configuration. It matches a ground-truth
item when the paths are equal after normalisation, the CWEs are equal or listed
as equivalent, and the reported line falls within the window around the item.
Each item is matched at most once per configuration and run, so a tool that
reports the same flaw twice is not credited twice.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal

GT_FIELDS = (
    "id",
    "file",
    "line_start",
    "line_end",
    "cwe",
    "kind",
    "origin",
    "cvss_vector",
    "labeller_a",
    "labeller_b",
    "agreed",
)

_TRUE = {"1", "true", "yes", "y"}


@dataclass(frozen=True)
class GTItem:
    id: str
    file: str
    line_start: int
    line_end: int
    cwe: str
    kind: Literal["vuln", "safe"]
    origin: Literal["builtin", "injected"]
    cvss_vector: str | None
    labeller_a: str
    labeller_b: str
    agreed: bool


@dataclass(frozen=True)
class Row:
    config: str
    run: int
    file: str
    line: int
    cwe: str
    severity: str | None
    cvss_vector: str | None
    stage: Literal["proposed", "after_g5", "baseline"]
    source_id: str


@dataclass
class MatchResult:
    tp: list[tuple[Row, GTItem]] = field(default_factory=list)
    fp: list[Row] = field(default_factory=list)
    fn: list[GTItem] = field(default_factory=list)
    tn: list[GTItem] = field(default_factory=list)
    duplicates: list[tuple[Row, GTItem]] = field(default_factory=list)


def normalise_path(value: str) -> str:
    """Repository-relative POSIX path with ``./`` and leading slashes removed."""
    text = value.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return str(PurePosixPath(text)).lstrip("/")


def normalise_cwe(value: str) -> str:
    text = value.strip().upper()
    if not text:
        return "CWE-UNKNOWN"
    return text if text.startswith("CWE-") else f"CWE-{text}"


def load_gt(path: Path) -> list[GTItem]:
    """Read a ground-truth CSV whose header is exactly ``GT_FIELDS``."""
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = set(GT_FIELDS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns {sorted(missing)}")
        items: list[GTItem] = []
        for raw in reader:
            items.append(
                GTItem(
                    id=raw["id"].strip(),
                    file=normalise_path(raw["file"]),
                    line_start=int(raw["line_start"]),
                    line_end=int(raw["line_end"]),
                    cwe=normalise_cwe(raw["cwe"]),
                    kind="safe" if raw["kind"].strip().lower() == "safe" else "vuln",
                    origin="injected" if raw["origin"].strip().lower() == "injected" else "builtin",
                    cvss_vector=(raw["cvss_vector"] or "").strip() or None,
                    labeller_a=raw["labeller_a"].strip(),
                    labeller_b=raw["labeller_b"].strip(),
                    agreed=raw["agreed"].strip().lower() in _TRUE,
                )
            )
    return items


def load_equivalence(path: Path) -> dict[str, frozenset[str]]:
    """Read ``cwe,equivalent`` pairs; equivalence is symmetric and reflexive."""
    table: dict[str, set[str]] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = {"cwe", "equivalent"} - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns {sorted(missing)}")
        for raw in reader:
            left = normalise_cwe(raw["cwe"])
            right = normalise_cwe(raw["equivalent"])
            table.setdefault(left, {left}).add(right)
            table.setdefault(right, {right}).add(left)
    return {cwe: frozenset(values) for cwe, values in table.items()}


def _cwe_matches(row_cwe: str, item_cwe: str, eq: dict[str, frozenset[str]]) -> bool:
    return row_cwe == item_cwe or item_cwe in eq.get(row_cwe, frozenset())


def _line_matches(row: Row, item: GTItem, window: int) -> bool:
    return item.line_start - window <= row.line <= item.line_end + window


def match(
    rows: list[Row],
    gt: list[GTItem],
    eq: dict[str, frozenset[str]],
    window: int = 3,
) -> MatchResult:
    """Score *rows* against the agreed ground truth, one pass per config and run."""
    agreed = [item for item in gt if item.agreed]
    vulnerable = [item for item in agreed if item.kind == "vuln"]
    safe = [item for item in agreed if item.kind == "safe"]

    groups: dict[tuple[str, int], list[Row]] = {}
    for row in rows:
        groups.setdefault((row.config, row.run), []).append(row)

    result = MatchResult()
    for group_rows in groups.values():
        matched: set[str] = set()
        for row in group_rows:
            row_path = normalise_path(row.file)
            row_cwe = normalise_cwe(row.cwe)
            candidate = next(
                (
                    item
                    for item in vulnerable
                    if item.id not in matched
                    and normalise_path(item.file) == row_path
                    and _cwe_matches(row_cwe, item.cwe, eq)
                    and _line_matches(row, item, window)
                ),
                None,
            )
            if candidate is not None:
                matched.add(candidate.id)
                result.tp.append((row, candidate))
                continue
            duplicate = next(
                (
                    item
                    for item in vulnerable
                    if item.id in matched
                    and normalise_path(item.file) == row_path
                    and _cwe_matches(row_cwe, item.cwe, eq)
                    and _line_matches(row, item, window)
                ),
                None,
            )
            if duplicate is not None:
                result.duplicates.append((row, duplicate))
                continue
            result.fp.append(row)
        result.fn.extend(item for item in vulnerable if item.id not in matched)
        hit_safe = {
            item.id
            for item in safe
            if any(
                normalise_path(item.file) == normalise_path(row.file)
                and _cwe_matches(normalise_cwe(row.cwe), item.cwe, eq)
                and _line_matches(row, item, window)
                for row in group_rows
            )
        }
        result.tn.extend(item for item in safe if item.id not in hit_safe)
    return result
