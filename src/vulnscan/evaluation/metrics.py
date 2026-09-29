"""Evaluation metrics — precision, recall, F1, unresolved rate, verification coverage.

Reports per-CWE and aggregate results with numerators/denominators,
separate Java/JSP coverage, and a separate dependency track.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnscan.contracts.enums import CWECategory, FindingStatus
from vulnscan.contracts.evaluation import EvaluationCase
from vulnscan.contracts.finding import Finding
from vulnscan.contracts.validation import ValidationDecision


@dataclass
class MatchResult:
    """A pairing between an evaluation case and a produced finding."""

    case_id: str
    finding_id: str | None
    matched: bool
    match_method: str  # "fingerprint", "location", "cwe", "none"
    cwe: CWECategory | None = None


@dataclass
class CWEResults:
    """Per-CWE metric counts."""

    cwe: str
    tp: int = 0  # true positive: confirmed finding matched to expected vulnerable case
    fp: int = 0  # false positive: confirmed finding with no matching expected case
    fn: int = 0  # false negative: expected vulnerable case with no confirmed finding
    tn: int = 0  # true negative: expected negative with no confirmed finding
    unresolved: int = 0
    verified: int = 0
    eligible_verification: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def unresolved_rate(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn + self.unresolved
        return self.unresolved / total if total > 0 else 0.0

    @property
    def verification_coverage(self) -> float:
        return self.verified / self.eligible_verification if self.eligible_verification > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cwe": self.cwe,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "unresolved": self.unresolved,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "unresolved_rate": round(self.unresolved_rate, 4),
            "verified": self.verified,
            "eligible_verification": self.eligible_verification,
            "verification_coverage": round(self.verification_coverage, 4),
        }


@dataclass
class AggregateResults:
    """Combined results across all CWEs."""

    per_cwe: dict[str, CWEResults] = field(default_factory=dict)
    total_tp: int = 0
    total_fp: int = 0
    total_fn: int = 0
    total_tn: int = 0
    total_unresolved: int = 0
    total_verified: int = 0
    total_eligible_verification: int = 0

    @property
    def precision(self) -> float:
        denom = self.total_tp + self.total_fp
        return self.total_tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.total_tp + self.total_fn
        return self.total_tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def verification_coverage(self) -> float:
        return (
            self.total_verified / self.total_eligible_verification
            if self.total_eligible_verification > 0
            else 0.0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tp": self.total_tp,
            "total_fp": self.total_fp,
            "total_fn": self.total_fn,
            "total_tn": self.total_tn,
            "total_unresolved": self.total_unresolved,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "verification_coverage": round(self.verification_coverage, 4),
            "per_cwe": {k: v.to_dict() for k, v in self.per_cwe.items()},
        }


def match_findings_to_cases(
    cases: list[EvaluationCase],
    findings: list[Finding],
) -> list[MatchResult]:
    """Pair evaluation cases with produced findings using matching criteria."""
    results = []
    used_findings: set[str] = set()

    for case in cases:
        if case.expected_cwe_category is None:
            # Negative case — no finding expected
            results.append(
                MatchResult(
                    case_id=case.case_id,
                    finding_id=None,
                    matched=False,
                    match_method="negative",
                    cwe=None,
                )
            )
            continue

        best_match = None
        for finding in findings:
            if finding.finding_id in used_findings:
                continue

            # CWE match
            if (
                case.matching_criteria.match_by_cwe
                and finding.cwe_category != case.expected_cwe_category
            ):
                continue

            # Location match
            if (
                case.matching_criteria.match_by_location
                and finding.observations
                and case.variant_path
            ):
                obs = finding.observations[0]
                if obs.location:
                    loc_match = obs.location.file_path == case.variant_path
                    if not loc_match:
                        continue
                else:
                    continue

            best_match = finding
            break

        if best_match:
            used_findings.add(best_match.finding_id)
            results.append(
                MatchResult(
                    case_id=case.case_id,
                    finding_id=best_match.finding_id,
                    matched=True,
                    match_method="location+cwe",
                    cwe=case.expected_cwe_category,
                )
            )
        else:
            results.append(
                MatchResult(
                    case_id=case.case_id,
                    finding_id=None,
                    matched=False,
                    match_method="none",
                    cwe=case.expected_cwe_category,
                )
            )

    return results


def compute_metrics(
    cases: list[EvaluationCase],
    findings: list[Finding],
    decisions: list[ValidationDecision] | None = None,
) -> AggregateResults:
    """Compute precision, recall, F1, unresolved rate, and verification coverage."""
    decisions = decisions or []
    decision_map = {d.finding_id: d for d in decisions}

    matches = match_findings_to_cases(cases, findings)
    aggregate = AggregateResults()

    # Group cases by expected CWE
    cwe_cases: dict[str, list[EvaluationCase]] = defaultdict(list)
    for c in cases:
        if c.expected_cwe_category:
            cwe_cases[c.expected_cwe_category.value].append(c)

    for cwe_val, cwe_case_list in cwe_cases.items():
        cwe_result = CWEResults(cwe=cwe_val)

        for case in cwe_case_list:
            match = next((m for m in matches if m.case_id == case.case_id), None)

            if case.variant_relationship.value == "fixed":
                # Fixed case — no finding expected
                if match and match.matched:
                    cwe_result.fp += 1  # False positive on fixed variant
                else:
                    cwe_result.tn += 1  # True negative
            elif case.variant_relationship.value == "vulnerable":
                # Vulnerable case — finding expected
                if match and match.matched:
                    cwe_result.tp += 1
                    # Check if verified via validation decision
                    if match.finding_id and match.finding_id in decision_map:
                        dec = decision_map[match.finding_id]
                        if dec.new_status == FindingStatus.CONFIRMED:
                            cwe_result.verified += 1
                        cwe_result.eligible_verification += 1
                    else:
                        cwe_result.eligible_verification += 1
                else:
                    cwe_result.fn += 1
            elif case.variant_relationship.value == "negative":
                # Negative case — no finding expected
                if match and match.matched:
                    cwe_result.fp += 1
                else:
                    cwe_result.tn += 1

            # Unresolved findings
            if match and match.finding_id and match.finding_id in decision_map:
                dec = decision_map[match.finding_id]
                if dec.new_status == FindingStatus.UNRESOLVED:
                    cwe_result.unresolved += 1

        aggregate.per_cwe[cwe_val] = cwe_result
        aggregate.total_tp += cwe_result.tp
        aggregate.total_fp += cwe_result.fp
        aggregate.total_fn += cwe_result.fn
        aggregate.total_tn += cwe_result.tn
        aggregate.total_unresolved += cwe_result.unresolved
        aggregate.total_verified += cwe_result.verified
        aggregate.total_eligible_verification += cwe_result.eligible_verification

    return aggregate


def save_metrics(results: AggregateResults, path: Path) -> None:
    """Save metrics to a JSON file."""
    path.write_text(
        json.dumps(results.to_dict(), indent=2),
        encoding="utf-8",
    )


def load_metrics(path: Path) -> dict[str, Any]:
    """Load metrics from a JSON file."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("metrics must be an object")
    return payload
