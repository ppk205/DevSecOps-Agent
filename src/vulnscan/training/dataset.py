"""Leakage-resistant triage dataset export (FR-40, QR-05, QR-17)."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

from vulnscan.contracts import Finding
from vulnscan.decisions.protocol import (
    INPUT_FORMAT_VERSION,
    MODEL_ID,
    MODEL_REVISION,
    QUESTION_SET_VERSION,
)
from vulnscan.decisions.state import build_evidence_state, model_state
from vulnscan.decisions.triage import build_triage_questions, finding_to_state

SPLITS = ("train", "validation", "calibration", "test")


def prepare(
    scans: list[dict[str, Any]], labels: list[dict[str, Any]], seed: int = 42
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    findings: dict[tuple[str, str], Finding] = {}
    for scan in scans:
        for raw in scan.get("findings", []):
            finding = Finding.model_validate(raw)
            key = (finding.run_id, finding.finding_id)
            if key in findings:
                raise ValueError("Duplicate finding identity in scan inputs")
            findings[key] = finding
    questions = {
        name: {"type": q.type.value, "instructions": q.instructions, "criteria": q.criteria}
        for name, q in build_triage_questions().items()
    }
    lanes = questions["recommended_action"]["criteria"]
    parent: dict[str, str] = {}

    def root(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    seen_states: dict[str, str] = {}
    for label in labels:
        key = (str(label["run_id"]), str(label["finding_id"]))
        if key in seen:
            raise ValueError("Duplicate reviewed label")
        seen.add(key)
        if (
            label.get("adjudicated") is not True
            or label.get("independently_adjudicated") is not True
        ):
            raise ValueError("Training labels require independent adjudication")
        reviewers = label.get("reviewers", [])
        if not isinstance(reviewers, list) or len(set(reviewers)) < 2:
            raise ValueError("Each label requires two distinct reviewers")
        if key not in findings:
            raise ValueError("Reviewed label has no matching scan finding")
        lane, score, human = (
            label["expected_route"],
            label["evidence_sufficiency"],
            label["needs_human_review"],
        )
        if (
            lane not in lanes
            or type(score) is not int
            or score not in (0, 1, 2)
            or type(human) is not bool
        ):
            raise ValueError("Invalid triage labels")
        project, family = str(label["project_id"]).strip(), str(label["case_family"]).strip()
        if not project or not family:
            raise ValueError("Project and case family are required")
        a, b = root("project:" + project), root("family:" + family)
        parent[b] = a
        state = finding_to_state(findings[key])
        # Operational IDs cannot explain a decision and create cross-run leakage.
        state.pop("run_id", None)
        state.pop("finding_id", None)
        envelope = build_evidence_state(state)
        digest = str(envelope["state_hash"])
        if digest in seen_states:
            # Identical model inputs cannot be distributed across splits.
            a, b = root("project:" + project), root(seen_states[digest])
            parent[b] = a
        seen_states[digest] = "project:" + project
        gold = {
            "recommended_action": {"probabilities": {name: float(name == lane) for name in lanes}},
            "evidence_sufficiency": {
                "probabilities": {str(i): float(i == score) for i in range(3)}
            },
            "needs_human_review": {
                "probabilities": {"false": float(not human), "true": float(human)}
            },
        }
        rows.append(
            {
                "state": model_state(envelope),
                "questions": questions,
                "gold": gold,
                "_group": "project:" + project,
                "_identity": key,
                "_lane": lane,
            }
        )
    groups = sorted({root(row["_group"]) for row in rows})
    if len(groups) < 4:
        raise ValueError(
            "At least four independent project/family groups are required for train, validation, calibration and test"
        )
    random.Random(seed).shuffle(groups)
    reserved = max(1, len(groups) // 10)
    counts = (len(groups) - 3 * reserved, reserved, reserved, reserved)
    membership: dict[str, str] = {}
    start = 0
    for split, count in zip(SPLITS, counts, strict=True):
        for group in groups[start : start + count]:
            membership[group] = split
        start += count
    result: dict[str, list[dict[str, Any]]] = {split: [] for split in SPLITS}
    provenance: list[dict[str, Any]] = []
    by_lane: dict[str, Counter[str]] = {split: Counter() for split in SPLITS}
    for row in rows:
        group = root(row["_group"])
        split = membership[group]
        provenance.append(
            {
                "run_id": row["_identity"][0],
                "finding_id": row["_identity"][1],
                "group": group,
                "split": split,
            }
        )
        by_lane[split][row["_lane"]] += 1
        result[split].append({k: row[k] for k in ("state", "questions", "gold")})
    manifest = {
        "schema_version": 1,
        "seed": seed,
        "model_id": MODEL_ID,
        "base_revision": MODEL_REVISION,
        "input_format_version": INPUT_FORMAT_VERSION,
        "question_set_version": QUESTION_SET_VERSION,
        "counts": {split: len(items) for split, items in result.items()},
        "route_counts": {split: dict(counts) for split, counts in by_lane.items()},
        "independent_groups": len(groups),
        "provenance": provenance,
    }
    return result, manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export independently adjudicated Laya triage data"
    )
    parser.add_argument("--scan", type=Path, action="append", required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    label_file = json.loads(args.labels.read_text(encoding="utf-8"))
    labels = label_file["rows"] if isinstance(label_file, dict) else label_file
    dataset, manifest = prepare(
        [json.loads(path.read_text(encoding="utf-8")) for path in args.scan], labels
    )
    args.out.mkdir(parents=True, exist_ok=True)
    manifest["checksums"] = {}
    for split, rows in dataset.items():
        data = "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ).encode()
        (args.out / f"{split}.jsonl").write_bytes(data)
        manifest["checksums"][split] = hashlib.sha256(data).hexdigest()
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {"counts": manifest["counts"], "independent_groups": manifest["independent_groups"]},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
