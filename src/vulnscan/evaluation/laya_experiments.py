"""Score one scan's advisory routing against evaluator-supplied ground truth.

The ground truth file is the only source of expectations. Nothing in the
advisory layer is allowed to write to it, and a finding status is never
consulted as the answer key — that would let the system grade itself.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnscan.decisions.protocol import (
    ERROR_CODES,
    MODEL_ID,
    MODEL_REVISION,
    QUESTION_SET_VERSION,
    STATUS_OWNER,
)
from vulnscan.evaluation.calibration import (
    build_routing_report,
    compute_calibration,
    reliability_diagram,
)

RELIABILITY_BINS = 10


@dataclass
class GroundTruthRow:
    """One graded finding. ``expected_route`` may be a lane name or a bool."""

    finding_id: str
    expected_route: str | bool | None
    cwe: str
    language: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> GroundTruthRow:
        return cls(
            finding_id=str(raw["finding_id"]),
            expected_route=raw.get("expected_route"),
            cwe=str(raw.get("cwe", "unknown")),
            language=str(raw.get("language", "unknown")),
        )


def load_ground_truth(path: Path) -> list[GroundTruthRow]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["rows"] if isinstance(data, dict) else data
    return [GroundTruthRow.from_dict(r) for r in rows]


def _answer(payload: dict[str, Any], name: str) -> dict[str, Any]:
    return (payload.get("answers") or {}).get(name) or {}


def _confidence(payload: dict[str, Any]) -> float | None:
    """Confidence the model reported for its own recommended action.

    Laya returns a per-answer ``confidence`` alongside the label. It is
    uncalibrated by construction, which is exactly why T09 measures it.
    """
    value = _answer(payload, "recommended_action").get("confidence")
    return float(value) if isinstance(value, (int, float)) else None


def evaluate_routing(
    payloads: Sequence[dict[str, Any]],
    ground_truth: Sequence[GroundTruthRow],
) -> dict[str, Any]:
    """Produce the T09 experiment record for one run's advisory routing."""
    truth = {row.finding_id: row for row in ground_truth}

    rows: list[dict[str, Any]] = []
    confidences: list[float] = []
    correct: list[bool] = []

    for payload in payloads:
        finding_id = str(payload.get("finding_id", ""))
        label = truth.get(finding_id)
        row: dict[str, Any] = {
            "finding_id": finding_id,
            "route": str(payload.get("route", "unknown")),
            "decision_status": str(payload.get("decision_status", "")),
            "error_code": payload.get("error_code"),
            "model_id": payload.get("model_id"),
            "model_revision": payload.get("model_revision"),
            "cwe": label.cwe if label else "unknown",
            "language": label.language if label else "unknown",
        }
        if label is not None and label.expected_route is not None:
            row["expected_route"] = label.expected_route

            confidence = _confidence(payload)
            escalated = row["route"] == "human_review"
            if isinstance(label.expected_route, bool):
                route_was_correct = escalated == label.expected_route
            else:
                route_was_correct = row["route"] == str(label.expected_route)

            if confidence is not None and row["decision_status"] == "completed":
                # Calibration is graded on route correctness: did the lane the
                # model picked actually match what the ground truth called for.
                confidences.append(confidence)
                correct.append(route_was_correct)

        rows.append(row)

    report = build_routing_report(rows)
    calibration = compute_calibration(confidences, correct)

    return {
        "protocol": {
            "model_id": MODEL_ID,
            "model_revision": MODEL_REVISION,
            "question_set_version": QUESTION_SET_VERSION,
            "status_owner": STATUS_OWNER,
            "advisory_only": True,
        },
        "routing": report.to_dict(),
        "calibration": calibration.to_dict(),
        "reliability_diagram": reliability_diagram(confidences, correct, RELIABILITY_BINS),
        "graded": len(rows),
        "ground_truth_matched": sum(1 for r in rows if "expected_route" in r),
        "error_codes_seen": sorted(
            {
                str(r["error_code"])
                for r in rows
                if r.get("error_code") and str(r["error_code"]) != "None"
            }
        ),
        "known_error_codes": ERROR_CODES,
    }


def evaluate_from_files(scan_json: Path, truth_path: Path) -> dict[str, Any]:
    """Evaluate a pipeline JSON export against a ground-truth file."""
    scan = json.loads(scan_json.read_text(encoding="utf-8"))
    payloads = scan.get("advisory_routing", {}).get("payloads", [])
    return evaluate_routing(payloads, load_ground_truth(truth_path))
