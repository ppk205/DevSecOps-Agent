"""Metrics are computed, never typed; partial runs are excluded from means."""

from __future__ import annotations

import json
from pathlib import Path

from vulnscan.experiment.evaluate import (
    Confusion,
    cost_metrics,
    evaluate,
    laya_effect,
    summarise,
)
from vulnscan.experiment.groundtruth import GTItem, Row

HEADER = "id,file,line_start,line_end,cwe,kind,origin,cvss_vector,labeller_a,labeller_b,agreed\n"
V1 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V2 = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def gt_rows(*lines: int) -> str:
    return "".join(
        f"g{line},src/A.java,{line},{line},CWE-89,vuln,builtin,{V1},A,B,true\n" for line in lines
    )


def write_run(
    root: Path, config: str, run: int, lines: list[int], status: str = "completed"
) -> None:
    run_dir = root / config / str(run)
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": f"f{index}",
                        "cwe": "CWE-89",
                        "cvss_vector": V2,
                        "path": [{"file": "src/A.java", "line": line}],
                    }
                    for index, line in enumerate(lines)
                ]
            }
        ),
        encoding="utf-8",
    )
    if status != "completed":
        (run_dir / "status.json").write_text(json.dumps({"status": status}), encoding="utf-8")


def test_precision_recall_f1_fpr_on_toy_set() -> None:
    c = Confusion(tp=2, fp=1, fn=1, tn=1)
    assert round(c.precision, 3) == 0.667
    assert round(c.recall, 3) == 0.667
    assert round(c.f1, 3) == 0.667
    assert c.fpr == 0.5


def test_summarise_is_mean_min_max() -> None:
    assert summarise([0.5, 1.0]) == {"mean": 0.75, "min": 0.5, "max": 1.0, "runs": 2}


def test_cvss_error_uses_score_cvss4(tmp_path: Path) -> None:
    gt = tmp_path / "gt.csv"
    gt.write_text(HEADER + gt_rows(10), encoding="utf-8")
    eq = tmp_path / "eq.csv"
    eq.write_text("cwe,equivalent\n", encoding="utf-8")
    runs = tmp_path / "runs"
    write_run(runs, "S2", 1, [10])
    out = tmp_path / "out"
    evaluate(gt, eq, runs, out)
    cvss = json.loads((out / "cvss.json").read_text(encoding="utf-8"))
    # AC:L scores higher than AC:H, so the error is the difference, not zero.
    assert cvss["S2"]["mean_error"] > 0
    assert cvss["S2"]["exact_share"] == 0.0


def test_partial_runs_reported_not_averaged(tmp_path: Path) -> None:
    gt = tmp_path / "gt.csv"
    gt.write_text(HEADER + gt_rows(10), encoding="utf-8")
    eq = tmp_path / "eq.csv"
    eq.write_text("cwe,equivalent\n", encoding="utf-8")
    runs = tmp_path / "runs"
    write_run(runs, "S2", 1, [10])
    write_run(runs, "S2", 2, [], status="partial")
    out = tmp_path / "out"
    evaluate(gt, eq, runs, out)
    metrics = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    aggregate = metrics["configs"]["S2"]["aggregate"]
    assert aggregate["completed_runs"] == 1
    assert aggregate["partial_runs"] == [2]
    assert aggregate["recall"]["mean"] == 1.0


def test_cost_per_tp(tmp_path: Path) -> None:
    metrics = {"configs": {"S2": {"aggregate": {"tp_total": 2}}}}
    run_dir = tmp_path / "S2" / "1"
    run_dir.mkdir(parents=True)
    (run_dir / "cost.json").write_text(
        json.dumps({"tokens": 1000, "usd": 0.5, "seconds": 30}), encoding="utf-8"
    )
    costs = cost_metrics(tmp_path, metrics)
    assert costs["S2"]["usd_per_tp"] == 0.25
    assert costs["S2"]["tokens_per_tp"] == 500.0


def test_tables_md_contains_every_config(tmp_path: Path) -> None:
    gt = tmp_path / "gt.csv"
    gt.write_text(HEADER + gt_rows(10), encoding="utf-8")
    eq = tmp_path / "eq.csv"
    eq.write_text("cwe,equivalent\n", encoding="utf-8")
    runs = tmp_path / "runs"
    write_run(runs, "S2", 1, [10])
    write_run(runs, "B1", 1, [99])
    out = tmp_path / "out"
    evaluate(gt, eq, runs, out)
    table = (out / "tables.md").read_text(encoding="utf-8")
    assert "| S2 |" in table and "| B1 |" in table
    assert (out / "charts" / "precision_recall.csv").is_file()


def test_laya_effect_reports_missing_side() -> None:
    assert laya_effect({"configs": {}}, {}) == {"available": False, "reason": "S1 or S2 missing"}


def test_gt_item_and_row_types_are_used_as_declared() -> None:
    item = GTItem("g1", "src/A.java", 1, 1, "CWE-89", "vuln", "builtin", None, "A", "B", True)
    row = Row("S2", 1, "src/A.java", 1, "CWE-89", None, None, "proposed", "f1")
    assert item.agreed and row.stage == "proposed"


def test_evaluate_separates_stages_and_writes_all_outputs(tmp_path: Path) -> None:
    gt = tmp_path / "gt.csv"
    gt.write_text(HEADER + gt_rows(10, 30))
    eq = tmp_path / "eq.csv"
    eq.write_text("cwe,equivalent\nCWE-639,CWE-862\n")
    runs = tmp_path / "runs"
    write_run(runs, "S2", 1, [10, 30])
    (runs / "S2/1/session.jsonl").write_text(
        json.dumps(
            {
                "type": "gate",
                "gate": "G5",
                "choice": "confirm",
                "person": "synthetic-reviewer",
                "payload": {"finding_id": "f0"},
            }
        )
    )
    written = evaluate(gt, eq, runs, tmp_path / "out")
    assert {"metrics", "cost", "human", "laya", "cvss", "tables"} <= written.keys()
    data = json.loads(written["metrics"].read_text())
    stages = data["configs"]["S2"]["runs"][0]["stages"]
    assert stages["proposed"]["overall"]["tp"] == 2
    assert stages["after_g5"]["overall"]["tp"] == 1
    assert stages["after_g5"]["overall"]["fn"] == 1
    assert "CWE-639" in written["tables"].read_text()


def test_unknown_measurements_are_null_and_skipped_runs_not_averaged(tmp_path: Path) -> None:
    gt = tmp_path / "gt.csv"
    gt.write_text(HEADER + gt_rows(10))
    eq = tmp_path / "eq.csv"
    eq.write_text("cwe,equivalent\n")
    runs = tmp_path / "runs"
    write_run(runs, "S2", 1, [], status="skipped")
    written = evaluate(gt, eq, runs, tmp_path / "out")
    data = json.loads(written["metrics"].read_text())["configs"]["S2"]
    assert data["aggregate"]["completed_runs"] == 0
    assert data["aggregate"]["recall"]["mean"] is None
    assert json.loads(written["cost"].read_text())["S2"]["usd"] is None


def test_cost_repetitions_use_sum_over_tp_sum_and_exclude_partial(tmp_path: Path) -> None:
    for n, status, usd in [(1, "completed", 1), (2, "completed", 3), (3, "partial", 90)]:
        run = tmp_path / "S2" / str(n)
        run.mkdir(parents=True)
        (run / "status.json").write_text(json.dumps({"status": status}))
        (run / "cost.json").write_text(json.dumps({"tokens": 100, "usd": usd, "seconds": 2}))
    metrics = {"configs": {"S2": {"aggregate": {"tp_total": 4}}}}
    cost = cost_metrics(tmp_path, metrics)["S2"]
    assert cost["usd_per_tp"] == 1
    assert cost["usd"] == 2


def test_session_usage_missing_price_and_gate_latency(tmp_path: Path) -> None:
    from vulnscan.experiment.evaluate import human_metrics

    root = tmp_path / "S2/1"
    root.mkdir(parents=True)
    events = [
        {"type": "session_start", "at": "2026-01-01T00:00:00Z"},
        {
            "type": "usage",
            "input_tokens": 10,
            "output_tokens": 5,
            "cost_usd": 0,
            "at": "2026-01-01T00:00:02Z",
        },
        {"type": "gate_request", "gate": "G5", "request_id": "r", "at": "2026-01-01T00:00:03Z"},
        {
            "type": "gate",
            "gate": "G5",
            "request_id": "r",
            "person": "synthetic",
            "choice": "confirm",
            "at": "2026-01-01T00:00:07Z",
        },
        {"type": "gate", "gate": "G2", "person": "auto", "choice": "approve"},
    ]
    (root / "session.jsonl").write_text("\n".join(json.dumps(e) for e in events))
    costs = cost_metrics(tmp_path, {"configs": {"S2": {"aggregate": {"tp_total": 1}}}})
    assert costs["S2"]["tokens"] == 15 and costs["S2"]["usd"] is None
    human = human_metrics(events)
    assert human["decisions"] == 1
    assert human["per_gate"]["G5"]["mean_seconds"] == 4


def test_malformed_scanner_not_completed_and_valid_empty_scan_has_fn(tmp_path: Path) -> None:
    from vulnscan.experiment.evaluate import load_dataset

    root = tmp_path / "B1/1"
    root.mkdir(parents=True)
    (root / "scanner-semgrep.json").write_text(
        '{"status":"completed","observations":[{"location":"bad"}]}'
    )
    gt = [GTItem("g", "A.java", 1, 1, "CWE-89", "vuln", "builtin", None, "A", "B", True)]
    assert load_dataset(tmp_path, gt, {})["B1"]["runs"][0]["status"] == "partial"
    (root / "scanner-semgrep.json").write_text('{"status":"completed","observations":[]}')
    record = load_dataset(tmp_path, gt, {})["B1"]["runs"][0]
    assert record["status"] == "completed" and record["overall"]["fn"] == 1
    assert record["overall"]["fpr"] is None


def test_after_g5_not_available_until_human_review(tmp_path: Path) -> None:
    from vulnscan.experiment.evaluate import load_dataset

    write_run(tmp_path, "S2", 1, [10])
    gt = [GTItem("g", "src/A.java", 10, 10, "CWE-89", "vuln", "builtin", None, "A", "B", True)]
    record = load_dataset(tmp_path, gt, {})["S2"]["runs"][0]
    assert record["stages"]["after_g5"]["status"] == "unavailable"


def test_evaluation_is_byte_identical_and_refuses_overwrite(tmp_path: Path) -> None:
    import pytest

    gt, eq = tmp_path / "gt.csv", tmp_path / "eq.csv"
    gt.write_text(HEADER + gt_rows(10))
    eq.write_text("cwe,equivalent\n")
    write_run(tmp_path / "runs", "S2", 1, [10])
    first = evaluate(gt, eq, tmp_path / "runs", tmp_path / "one")
    second = evaluate(gt, eq, tmp_path / "runs", tmp_path / "two")
    assert {key: p.read_bytes() for key, p in first.items()} == {
        key: p.read_bytes() for key, p in second.items()
    }
    with pytest.raises(FileExistsError):
        evaluate(gt, eq, tmp_path / "runs", tmp_path / "one")


def test_scanner_duration_uses_envelope_and_unknown_cost_stays_unknown(tmp_path: Path) -> None:
    root = tmp_path / "B1/1"
    root.mkdir(parents=True)
    (root / "scanner-semgrep.json").write_text(
        json.dumps({"duration_ms": 2500, "observations": []})
    )
    costs = cost_metrics(tmp_path, {"configs": {"B1": {"aggregate": {"tp_total": 0}}}})
    assert costs["B1"]["seconds"] == 2.5
    assert costs["B1"]["usd"] is None
