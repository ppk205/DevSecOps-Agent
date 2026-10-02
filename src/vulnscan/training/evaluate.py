"""Evaluate frozen Laya triage checkpoints without exposing labels to inference."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

from vulnscan.contracts.decision import DecisionRequest, DecisionStatus
from vulnscan.decisions.decision_requests import to_decision_questions
from vulnscan.decisions.laya import LayaDecisionBackend
from vulnscan.decisions.protocol import MODEL_REVISION, REVIEW_THRESHOLD
from vulnscan.decisions.router import DecisionRouter
from vulnscan.evaluation.calibration import compute_calibration


def summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    available = [r for r in rows if r["available"]]
    by_route: dict[str, Any] = {}
    f1_scores: list[float] = []
    for lane in sorted({str(r["expected_route"]) for r in rows}):
        tp = sum(r["expected_route"] == lane and r["raw_route"] == lane for r in available)
        fp = sum(r["expected_route"] != lane and r["raw_route"] == lane for r in available)
        fn = sum(r["expected_route"] == lane and r["raw_route"] != lane for r in available)
        support = sum(r["expected_route"] == lane for r in rows)
        denominator = 2 * tp + fp + fn
        f1 = 2 * tp / denominator if denominator else None
        if f1 is not None:
            f1_scores.append(f1)
        by_route[lane] = {
            "support": support,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": f1,
        }
    confidences = [float(r["top_probability"]) for r in available]
    correct = [r["raw_route"] == r["expected_route"] for r in available]
    human_tp = sum(r["human_prediction"] and r["expected_human"] for r in available)
    human_fp = sum(r["human_prediction"] and not r["expected_human"] for r in available)
    human_fn = sum(not r["human_prediction"] and r["expected_human"] for r in available)
    latencies = sorted(float(r["latency_ms"]) for r in rows)
    return {
        "total": len(rows),
        "available": len(available),
        "unavailable": len(rows) - len(available),
        "raw_route_accuracy": sum(correct) / len(available) if available else None,
        "policy_route_accuracy": sum(r["policy_route"] == r["expected_route"] for r in available)
        / len(available)
        if available
        else None,
        "macro_f1": statistics.mean(f1_scores) if f1_scores else None,
        "by_route": by_route,
        "dangerous_downgrades": sum(
            r["policy_route"] == "low_priority" and r["expected_route"] != "low_priority"
            for r in available
        ),
        "human_review_precision": human_tp / (human_tp + human_fp) if human_tp + human_fp else None,
        "human_review_recall": human_tp / (human_tp + human_fn) if human_tp + human_fn else None,
        "missed_human_reviews": human_fn,
        "unnecessary_human_reviews": human_fp,
        "evidence_score_mae": statistics.mean(
            abs(r["score"] - r["expected_score"]) for r in available
        )
        if available
        else None,
        "calibration": compute_calibration(confidences, correct).to_dict(),
        "latency_p50_ms": statistics.median(latencies) if latencies else None,
        "latency_p95_ms": latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
        if latencies
        else None,
        "confusion": dict(Counter(f"{r['expected_route']}->{r['raw_route']}" for r in available)),
    }


def evaluate(rows: list[dict[str, Any]], backend: LayaDecisionBackend) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for row in rows:
        request = DecisionRequest(
            state=row["state"], questions=to_decision_questions(row["questions"])
        )
        result = backend.predict(request)
        # Labels are accessed only after inference returns.
        gold = row["gold"]
        expected_route = max(
            gold["recommended_action"]["probabilities"],
            key=gold["recommended_action"]["probabilities"].get,
        )
        expected_score = int(
            max(
                gold["evidence_sufficiency"]["probabilities"],
                key=gold["evidence_sufficiency"]["probabilities"].get,
            )
        )
        expected_human = gold["needs_human_review"]["probabilities"]["true"] >= REVIEW_THRESHOLD
        item = {
            "available": result.status is DecisionStatus.COMPLETED,
            "expected_route": expected_route,
            "expected_score": expected_score,
            "expected_human": expected_human,
            "model_id": result.model_id,
            "model_revision": result.model_revision,
            "device": result.device,
            "latency_ms": result.latency_ms,
            "error_code": result.error_code,
        }
        if item["available"]:
            action = result.answers["recommended_action"]
            policy = DecisionRouter().route(
                request=request, result=result, final_status="unprocessed"
            )
            item.update(
                raw_route=action.choice,
                policy_route=policy.route,
                top_probability=max(action.probabilities.values(), default=action.confidence),
                score=result.answers["evidence_sufficiency"].score,
                human_prediction=(result.answers["needs_human_review"].noul or 0)
                >= REVIEW_THRESHOLD,
            )
        results.append(item)
    return {"metrics_schema_version": 2, "summary": summary(results), "rows": results}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate a frozen triage checkpoint on untouched test data"
    )
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--device", default="auto")
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.test.read_text(encoding="utf-8").splitlines() if line]
    backend = LayaDecisionBackend(
        model_id=args.model,
        model_revision=None if Path(args.model).is_dir() else MODEL_REVISION,
        device=args.device,
        timeout_seconds=120,
    )
    report = evaluate(rows, backend)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
