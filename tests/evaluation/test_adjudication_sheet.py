"""The sheet builder renders evidence only; labelling lives in a separate step.

``build_sheet`` must not invent labels. ``scripts/label_sheet.py`` applies
labels afterwards and stamps every row with its provenance, because the
evaluating agent is also the one that built the pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.evaluation.adjudication_sheet import build_sheet, render_text

REPO = Path(__file__).resolve().parents[2]


def _scan() -> dict:
    return {
        "findings": [
            {
                "finding_id": "F1",
                "cwe_category": "CWE-89",
                "severity": "high",
                "observations": [
                    {
                        "rule_id": "java.sql",
                        "message": "Detected a formatted string in a SQL statement.",
                        "location": {
                            "file_path": "src/main/java/dao/CartDAO.java",
                            "line_start": 3,
                        },
                    }
                ],
            }
        ],
        "advisory_routing": {
            "payloads": [
                {
                    "finding_id": "F1",
                    "route": "human_review",
                    "answers": {
                        "recommended_action": {"confidence": 0.42, "probabilities": {"a": 0.6, "b": 0.4}},
                        "needs_human_review": {"noul": 0.3},
                        "evidence_sufficiency": {"score": 0.8},
                    },
                }
            ]
        },
    }


def test_sheet_carries_model_output_and_evidence(tmp_path: Path) -> None:
    src = tmp_path / "src" / "main" / "java" / "dao"
    src.mkdir(parents=True)
    (src / "CartDAO.java").write_text(
        "line1\nline2\nstmt.execute(\"SELECT \" + id);\nline4\n", encoding="utf-8"
    )

    rows = build_sheet(_scan(), tmp_path)

    assert len(rows) == 1
    row = rows[0]
    assert row["cwe"] == "CWE-89"
    assert row["laya_route"] == "human_review"
    assert row["laya_confidence"] == 0.42
    assert row["rule_id"] == "java.sql"
    assert "stmt.execute" in (row["source"] or "")


def test_every_row_leaves_the_label_blank(tmp_path: Path) -> None:
    rows = build_sheet(_scan(), tmp_path)

    assert rows[0]["expected_route"] is None


def test_sheet_degrades_when_source_is_unreachable(tmp_path: Path) -> None:
    rows = build_sheet(_scan(), tmp_path)

    assert rows[0]["source"] is None
    assert "not reachable" in render_text(rows)


def test_absolute_scan_paths_resolve_back_into_the_checkout(tmp_path: Path) -> None:
    checkout = tmp_path / "repo"
    src = checkout / "src" / "main" / "java" / "dao"
    src.mkdir(parents=True)
    (src / "CartDAO.java").write_text("a\nb\nvuln\nd\n", encoding="utf-8")

    scan = _scan()
    # A scan records the absolute path from the machine that ran it; only the
    # part after src/ should be re-resolved against the local checkout.
    scan["findings"][0]["observations"][0]["location"]["file_path"] = (
        "D:/scan/host/root/src/main/java/dao/CartDAO.java"
    )

    rows = build_sheet(scan, checkout)

    assert rows[0]["source"] is not None
    assert "vuln" in rows[0]["source"]


def test_text_sheet_shows_the_blank_label_for_a_human(tmp_path: Path) -> None:
    text = render_text(build_sheet(_scan(), tmp_path))

    assert "expected_route: None" in text
    assert "human_review" in text


def test_rows_are_ordered_by_route_then_cwe(tmp_path: Path) -> None:
    scan = _scan()
    second = json.loads(json.dumps(scan))
    second["findings"][0]["finding_id"] = "F0"
    second["findings"][0]["cwe_category"] = "CWE-79"
    second["advisory_routing"]["payloads"][0]["finding_id"] = "F0"
    second["advisory_routing"]["payloads"][0]["route"] = "human_review"
    scan["advisory_routing"]["payloads"][0]["cwe"] = "CWE-79"

    merged = {
        "findings": scan["findings"] + second["findings"],
        "advisory_routing": {
            "payloads": scan["advisory_routing"]["payloads"]
            + second["advisory_routing"]["payloads"]
        },
    }

    rows = build_sheet(merged, tmp_path)

    assert [r["cwe"] for r in rows] == sorted(r["cwe"] for r in rows)


def test_real_sheet_covers_all_29_findings() -> None:
    path = REPO / "evidence" / "t09" / "adjudication_sheet.json"
    if not path.is_file():
        return  # scan not run yet; nothing to assert

    rows = json.loads(path.read_text(encoding="utf-8"))
    assert len(rows) == 29
    assert all(r["source"] for r in rows)
    # A row is complete only when the label carries its own provenance: a
    # route with no verdict or reason is a half-finished review.
    for row in rows:
        assert row["expected_route"] is not None, f"unlabelled: {row['finding_id']}"
        assert row["verdict"] in {"true_positive", "false_positive"}
        assert row["label_reason"].strip()
        assert row["independently_adjudicated"] is False
        assert row["labelled_by"]


def test_experiment_record_carries_the_label_caveat() -> None:
    """Metrics must not be readable as independent validation.

    The agent that graded Laya is the agent that built the pipeline, so the
    record has to say so wherever the numbers live, not only in a commit
    message.
    """
    path = REPO / "evidence" / "t09" / "eval_agentlabels.json"
    if not path.is_file():
        return  # evaluation not run yet; nothing to assert

    record = json.loads(path.read_text(encoding="utf-8"))
    provenance = record["label_provenance"]
    assert provenance["independently_adjudicated"] is False
    assert provenance["labelled_by"] == "devsecops-agent"
    assert "NOT independent validation" in provenance["caveat"]
    assert record["routing"]["route_accuracy"] is not None
