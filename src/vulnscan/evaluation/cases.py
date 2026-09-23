"""Evaluation case management — loading, validation, and split management.

Case families group related vulnerable/fixed/negative variants.  Labels and
fixed-variant references are evaluator-only and must never be exposed
through scanner or agent input mounts.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC
from pathlib import Path
from typing import Any

from vulnscan.contracts.enums import (
    CWECategory,
    Severity,
    SplitMembership,
    VariantRelationship,
)
from vulnscan.contracts.evaluation import EvaluationCase, MatchingCriteria


def load_cases(path: Path) -> list[EvaluationCase]:
    """Load evaluation cases from a JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [EvaluationCase(**item) for item in data]


def save_cases(cases: list[EvaluationCase], path: Path) -> None:
    """Save evaluation cases to a JSON file."""
    path.write_text(
        json.dumps([c.model_dump(mode="json") for c in cases], indent=2),
        encoding="utf-8",
    )


def validate_cases(cases: list[EvaluationCase]) -> list[str]:
    """Validate a set of evaluation cases. Returns list of error strings."""
    errors: list[str] = []
    ids: set[str] = set()
    for c in cases:
        if c.case_id in ids:
            errors.append(f"Duplicate case_id: {c.case_id}")
        ids.add(c.case_id)

        if c.split == SplitMembership.HELD_OUT and c.variant_relationship == VariantRelationship.REGRESSION:
            errors.append(
                f"Case {c.case_id}: regression variant cannot be held-out "
                f"(must be in same split as parent)"
            )
    return errors


def case_families(cases: list[EvaluationCase]) -> dict[str, list[EvaluationCase]]:
    """Group cases by case_family."""
    groups: dict[str, list[EvaluationCase]] = defaultdict(list)
    for c in cases:
        groups[c.case_family].append(c)
    return dict(groups)


def split_summary(cases: list[EvaluationCase]) -> dict[str, Any]:
    """Return a summary of the dataset splits."""
    split_counts = Counter(c.split.value for c in cases)
    vuln = [c for c in cases if c.expected_cwe_category is not None]
    vuln_by_split = Counter(c.split.value for c in vuln)
    return {
        "total_cases": len(cases),
        "by_split": dict(split_counts),
        "vulnerable_cases": len(vuln),
        "vulnerable_by_split": dict(vuln_by_split),
        "families": len(case_families(cases)),
    }


def create_sample_cases() -> list[EvaluationCase]:
    """Create sample evaluation cases for testing.

    Three CWE groups with one dev + two held-out cases each.
    Covers CWE-89, CWE-79, CWE-862.
    """
    from datetime import datetime
    now = datetime(2026, 1, 1, tzinfo=UTC)
    cases: list[EvaluationCase] = []

    cwe_groups = [
        (CWECategory.SQL_INJECTION, "sql-inject", "SQL Injection in login query"),
        (CWECategory.XSS, "xss-search", "Reflected XSS in search endpoint"),
        (CWECategory.BROKEN_ACCESS_CONTROL, "idor-profile", "IDOR in user profile access"),
    ]

    for i, (cwe, slug, title) in enumerate(cwe_groups):
        family = f"family-{slug}"
        splits = [
            (SplitMembership.DEVELOPMENT, VariantRelationship.VULNERABLE, cwe),
            (SplitMembership.HELD_OUT, VariantRelationship.VULNERABLE, cwe),
            (SplitMembership.HELD_OUT, VariantRelationship.FIXED, None),
        ]
        for j, (split, var_rel, expected_cwe) in enumerate(splits):
            case_id = f"{family}-case-{j+1}"
            is_fixed = var_rel == VariantRelationship.FIXED
            cases.append(EvaluationCase(
                case_id=case_id,
                case_family=family,
                split=split,
                variant_relationship=var_rel,
                expected_cwe_category=expected_cwe,
                expected_severity=Severity.HIGH,
                source_commit_sha="dd48d1240fdbc3e5b2ffe8b0a2e3ad65e10d57f5",
                variant_path=f"harness/JVA-bookstore-{slug}-{'fixed' if is_fixed else 'vulnerable'}",
                matching_criteria=MatchingCriteria(),
                created_at=now,
            ))

    return cases
