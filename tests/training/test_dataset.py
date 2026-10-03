"""Independent labels, grouped splits and canonical inference inputs."""

import json
from copy import deepcopy

import pytest

from tests.decisions.test_batching import _finding
from vulnscan.training.dataset import prepare


def inputs(count=20):
    findings, labels = [], []
    for index in range(count):
        finding = _finding(f"f-{index}").model_copy(update={"run_id": f"run-{index}"})
        findings.append(finding.model_dump(mode="json"))
        labels.append(
            {
                "run_id": finding.run_id,
                "finding_id": finding.finding_id,
                "project_id": f"project-{index}",
                "case_family": f"family-{index}",
                "expected_route": "cross_file_analysis",
                "evidence_sufficiency": 1,
                "needs_human_review": False,
                "adjudicated": True,
                "independently_adjudicated": True,
                "reviewers": ["reviewer-a", "reviewer-b"],
            }
        )
    return [{"findings": findings}], labels


def test_training_requires_independent_review():
    scans, labels = inputs()
    labels[0]["independently_adjudicated"] = False
    with pytest.raises(ValueError, match="independent adjudication"):
        prepare(scans, labels)


def test_related_projects_and_families_stay_in_one_split():
    scans, labels = inputs()
    labels[0]["case_family"] = labels[1]["case_family"]
    labels[1]["project_id"] = labels[2]["project_id"]
    splits, manifest = prepare(scans, labels)
    assignments = {row["finding_id"]: row["split"] for row in manifest["provenance"]}
    assert assignments["f-0"] == assignments["f-1"] == assignments["f-2"]
    assert all(splits[name] for name in splits)
    assert sum(len(items) for items in splits.values()) == 20
    assert prepare(scans, deepcopy(labels)) == (splits, manifest)


def test_labels_and_operational_ids_are_excluded_from_model_inputs():
    scans, labels = inputs()
    splits, _ = prepare(scans, labels)
    for rows in splits.values():
        for row in rows:
            assert "finding_id" not in row["state"] and "run_id" not in row["state"]
            assert "expected_route" not in row["state"] and "status" not in row["state"]
            assert row["state"]["cwe_category"] == "CWE-89"
            assert row["state"]["tool_names"] == ["semgrep"]
            assert json.dumps(row["gold"])


def test_one_project_cannot_be_split_into_four_sets():
    scans, labels = inputs()
    for label in labels:
        label["project_id"] = "one-project"
    with pytest.raises(ValueError, match="four independent"):
        prepare(scans, labels)
