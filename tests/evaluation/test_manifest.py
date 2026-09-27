"""The manifest must report gaps rather than hide them."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.evaluation.manifest import (
    REQUIRED_ARTIFACTS,
    build_manifest,
    describe,
    ground_truth_state,
)

REPO = Path(__file__).resolve().parents[2]


def test_every_required_artifact_is_hashed() -> None:
    manifest = build_manifest(REPO)
    paths = {a["path"] for a in manifest["artifacts"]}

    assert paths == set(REQUIRED_ARTIFACTS)
    for artifact in manifest["artifacts"]:
        assert artifact["present"], f"{artifact['path']} is missing from the repo"
        assert artifact["sha256"] and len(artifact["sha256"]) == 64
        assert artifact["size_bytes"] > 0


def test_missing_artifact_is_reported_not_skipped(tmp_path: Path) -> None:
    artifact = describe("docs/REPRODUCTION.md", tmp_path)

    assert artifact.present is False
    assert artifact.sha256 is None


def test_manifest_lists_missing_paths_as_blockers(tmp_path: Path) -> None:
    manifest = build_manifest(tmp_path)

    assert manifest["missing_artifacts"]
    assert any("Missing required handover artifacts" in b for b in manifest["blockers"])


def test_unadjudicated_ground_truth_is_a_blocker(tmp_path: Path) -> None:
    truth_dir = tmp_path / "evidence" / "t09"
    truth_dir.mkdir(parents=True)
    (truth_dir / "ground_truth.json").write_text(
        json.dumps({"adjudicated": False, "rows": []}), encoding="utf-8"
    )

    state = ground_truth_state(tmp_path)
    manifest = build_manifest(tmp_path)

    assert state == {"present": True, "adjudicated": False, "rows": 0}
    assert any("no adjudicated ground truth" in b for b in manifest["blockers"])


def test_adjudicated_ground_truth_clears_that_blocker(tmp_path: Path) -> None:
    truth_dir = tmp_path / "evidence" / "t09"
    truth_dir.mkdir(parents=True)
    (truth_dir / "ground_truth.json").write_text(
        json.dumps({"adjudicated": True, "rows": [{"finding_id": "F1"}]}), encoding="utf-8"
    )

    state = ground_truth_state(tmp_path)

    assert state["adjudicated"] is True
    assert state["rows"] == 1
    assert not any("ground truth" in b for b in build_manifest(tmp_path)["blockers"])


def test_manifest_pins_the_frozen_protocol() -> None:
    protocol = build_manifest(REPO)["protocol"]

    assert protocol["model_revision"] == "aa8c91ca088ec597df95a0d1c76b3063cb2ae5e8"
    assert protocol["status_owner"] == "IndependentValidator"
    assert protocol["contract_version"] == "decision-contract-1"


def test_real_repo_has_no_missing_artifacts() -> None:
    assert build_manifest(REPO)["missing_artifacts"] == []
