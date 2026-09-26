"""Calibration and routing-quality metrics for advisory decisions.

These are the numbers T09 must report. Nothing here reads a finding status: the
advisory layer is scored against ground truth supplied by the caller, so a model
answer can be graded without ever being trusted to set a status.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

CONFIDENCE_BINS = 10


@dataclass(frozen=True)
class Calibration:
    """Expected Calibration Error and Brier score for one confidence series."""

    n: int
    ece: float
    brier: float
    mean_confidence: float
    accuracy: float

    def to_dict(self) -> dict[str, Any]:
        # Every score is None when nothing was graded. A zero here would read
        # as a measured result, which is the one thing T09 must not invent.
        if self.n == 0:
            return {
                "n": 0,
                "ece": None,
                "brier": None,
                "mean_confidence": None,
                "accuracy": None,
            }
        return {
            "n": self.n,
            "ece": round(self.ece, 6),
            "brier": round(self.brier, 6),
            "mean_confidence": round(self.mean_confidence, 6),
            "accuracy": round(self.accuracy, 6),
        }


@dataclass(frozen=True)
class ReliabilityBin:
    """One reliability-diagram bin: predicted vs observed correctness."""

    lo: float
    hi: float
    count: int
    mean_confidence: float
    accuracy: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "lo": round(self.lo, 4),
            "hi": round(self.hi, 4),
            "count": self.count,
            "mean_confidence": round(self.mean_confidence, 6),
            "accuracy": round(self.accuracy, 6),
        }


def compute_calibration(
    confidences: list[float],
    correct: list[bool],
    bins: int = CONFIDENCE_BINS,
) -> Calibration:
    """ECE and Brier score over equal-width confidence bins.

    ``correct`` records whether the outcome the model predicted for an item
    actually occurred; it is supplied by the evaluator, never inferred from a
    model answer.
    """
    if len(confidences) != len(correct):
        raise ValueError("confidences and correct must be the same length")
    if not confidences:
        return Calibration(n=0, ece=0.0, brier=0.0, mean_confidence=0.0, accuracy=0.0)

    total = len(confidences)
    accuracy = sum(correct) / total
    brier = sum(
        (conf - (1.0 if ok else 0.0)) ** 2 for conf, ok in zip(confidences, correct, strict=True)
    ) / total

    ece = 0.0
    for lo in range(bins):
        low, high = lo / bins, (lo + 1) / bins
        last = lo == bins - 1
        bucket = [
            (c, k)
            for c, k in zip(confidences, correct, strict=True)
            if (low <= c < high) or (last and c == 1.0)
        ]
        if not bucket:
            continue
        share = len(bucket) / total
        bucket_conf = sum(c for c, _ in bucket) / len(bucket)
        bucket_acc = sum(1 for _, k in bucket if k) / len(bucket)
        ece += share * abs(bucket_acc - bucket_conf)

    return Calibration(
        n=total,
        ece=ece,
        brier=brier,
        mean_confidence=sum(confidences) / total,
        accuracy=accuracy,
    )


def reliability_diagram(
    confidences: list[float],
    correct: list[bool],
    bins: int = CONFIDENCE_BINS,
) -> list[dict[str, Any]]:
    """Per-bin predicted-vs-observed accuracy for a reliability diagram."""
    if len(confidences) != len(correct):
        raise ValueError("confidences and correct must be the same length")

    diagram: list[dict[str, Any]] = []
    for lo in range(bins):
        low, high = lo / bins, (lo + 1) / bins
        last = lo == bins - 1
        bucket = [
            (c, k)
            for c, k in zip(confidences, correct, strict=True)
            if (low <= c < high) or (last and c == 1.0)
        ]
        if not bucket:
            continue
        diagram.append(
            ReliabilityBin(
                lo=low,
                hi=high,
                count=len(bucket),
                mean_confidence=sum(c for c, _ in bucket) / len(bucket),
                accuracy=sum(1 for _, k in bucket if k) / len(bucket),
            ).to_dict()
        )
    return diagram


@dataclass
class RoutingReport:
    """Route distribution, escalation quality, and per-slice breakdowns."""

    total: int
    route_counts: dict[str, int] = field(default_factory=dict)
    unavailable: int = 0
    false_escalations: int = 0
    correct_routes: int = 0
    scored_routes: int = 0
    by_cwe: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_language: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def route_accuracy(self) -> float | None:
        """``None`` when nothing was scored — zero scored is not 0% accuracy."""
        return self.correct_routes / self.scored_routes if self.scored_routes else None

    @property
    def false_escalation_rate(self) -> float | None:
        return self.false_escalations / self.scored_routes if self.scored_routes else None

    @staticmethod
    def _rate(value: float | None) -> float | None:
        return None if value is None else round(value, 6)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "route_counts": dict(sorted(self.route_counts.items(), key=lambda kv: -kv[1])),
            "unavailable": self.unavailable,
            "route_accuracy": self._rate(self.route_accuracy),
            "false_escalations": self.false_escalations,
            "false_escalation_rate": self._rate(self.false_escalation_rate),
            "scored_routes": self.scored_routes,
            "by_cwe": self.by_cwe,
            "by_language": self.by_language,
        }


def _slice_stats(entries: list[tuple[bool, bool]]) -> dict[str, Any]:
    """Correct count and mean for a slice, tolerating an empty slice."""
    if not entries:
        return {"n": 0, "correct": 0, "accuracy": 0.0}
    correct = sum(1 for ok, _ in entries if ok)
    return {
        "n": len(entries),
        "correct": correct,
        "accuracy": round(correct / len(entries), 6),
    }


def build_routing_report(
    rows: list[dict[str, Any]],
    expected_route_key: str = "expected_route",
) -> RoutingReport:
    """Grade advisory routes against caller-supplied expectations.

    Each row needs ``route``, ``cwe`` and ``language``; rows carrying
    ``expected_route`` are scored, the rest only counted. ``True`` in
    ``expected_route`` means the finding was worth a human, so any escalation
    to ``human_review`` counts as correct and a non-escalation as a false
    escalation.
    """
    report = RoutingReport(total=len(rows))

    cwe_buckets: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
    lang_buckets: dict[str, list[tuple[bool, bool]]] = defaultdict(list)

    for row in rows:
        route = str(row.get("route", "unknown"))
        report.route_counts[route] = report.route_counts.get(route, 0) + 1

        if row.get("decision_status") != "completed":
            report.unavailable += 1

        expected = row.get(expected_route_key)
        if expected is None:
            continue

        if isinstance(expected, bool):
            # Boolean expectation: was this finding worth a human? Then the
            # only thing to grade is whether it escalated.
            should_escalate = expected
            escalated = route == "human_review"
            correct = escalated == should_escalate
            if should_escalate and not escalated:
                report.false_escalations += 1
        else:
            # A named lane is graded as an exact match, so a correctly routed
            # cross_file_analysis must not count as a miss for not escalating.
            should_escalate = route == str(expected)
            correct = route == str(expected)

        report.scored_routes += 1
        report.correct_routes += int(correct)

        cwe_buckets[str(row.get("cwe", "unknown"))].append((correct, should_escalate))
        lang_buckets[str(row.get("language", "unknown"))].append((correct, should_escalate))

    report.by_cwe = {k: _slice_stats(v) for k, v in sorted(cwe_buckets.items())}
    report.by_language = {k: _slice_stats(v) for k, v in sorted(lang_buckets.items())}
    return report
