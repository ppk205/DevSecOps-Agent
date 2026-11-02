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
