"""Compute the experiment's metrics, tables and chart inputs.

Every number written here is derived from rows produced by the normalisers and
the ground truth; nothing is typed in. Repeated runs are reported as mean, min
and max, and a run marked ``partial`` is listed on its own and excluded from
the means instead of being averaged in as if it had completed.
"""

from __future__ import annotations

import argparse
import json
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnscan.experiment.groundtruth import (
    GTItem,
    MatchResult,
    Row,
    load_equivalence,
    load_gt,
    match,
)
from vulnscan.experiment.normalize import from_b6, from_harness, from_sarif, from_scan_run
from vulnscan.harness.evidence import score_cvss4

CONFIGS = ("B1", "B2", "B3", "B4", "B5", "B6", "B7", "S1", "S2", "S3", "F1", "F2", "F3", "F4", "R1")
STAGES = ("baseline", "proposed", "after_g5")


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
        }


def confusion(result: MatchResult) -> Confusion:
    return Confusion(tp=len(result.tp), fp=len(result.fp), fn=len(result.fn), tn=len(result.tn))


def by_cwe(result: MatchResult) -> dict[str, Confusion]:
    table: dict[str, Confusion] = {}
    for _row, item in result.tp:
        table.setdefault(item.cwe, Confusion()).tp += 1
    for row in result.fp:
        table.setdefault(row.cwe, Confusion()).fp += 1
    for item in result.fn:
        table.setdefault(item.cwe, Confusion()).fn += 1
    for item in result.tn:
        table.setdefault(item.cwe, Confusion()).tn += 1
    return table


def cvss_error(result: MatchResult) -> dict[str, float | int]:
    errors: list[float] = []
    exact = 0
    for row, item in result.tp:
        if not row.cvss_vector or not item.cvss_vector:
            continue
        try:
            errors.append(abs(score_cvss4(row.cvss_vector) - score_cvss4(item.cvss_vector)))
        except ValueError:
            continue
        exact += row.cvss_vector.strip() == item.cvss_vector.strip()
    return {
        "pairs": len(errors),
        "mean_error": round(statistics.fmean(errors), 4) if errors else 0.0,
        "max_error": round(max(errors), 4) if errors else 0.0,
        "exact_share": round(exact / len(errors), 4) if errors else 0.0,
    }


def summarise(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "min": 0.0, "max": 0.0, "runs": 0}
    return {
        "mean": round(statistics.fmean(values), 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "runs": len(values),
    }


def load_run(rows_dir: Path, config: str, run: int) -> list[Row]:
    """Rows for one run directory, using whichever source it holds."""
    rows: list[Row] = []
    sarif = rows_dir / "codeql.sarif"
    if sarif.is_file():
        rows.extend(from_sarif(sarif, config))
    if (rows_dir / "report.json").is_file():
        session = rows_dir / "session.jsonl"
        rows.extend(from_harness(rows_dir / "report.json", session, config, run))
    if (rows_dir / "b6.jsonl").is_file():
        rows.extend(from_b6(rows_dir / "b6.jsonl", config, run))
    if any(rows_dir.glob("scanner-*.json")) or (rows_dir / "hunt.json").is_file():
        rows.extend(from_scan_run(rows_dir, config))
    return rows


def load_dataset(runs: Path, gt: list[GTItem], eq: dict[str, frozenset[str]]) -> dict[str, Any]:
    """Group every run under ``<runs>/<config>/<n>/`` and score it."""
    per_config: dict[str, dict[str, Any]] = {}
    for config_dir in sorted(p for p in runs.iterdir() if p.is_dir()):
        config = config_dir.name
        runs_out: list[dict[str, Any]] = []
        for run_dir in sorted(p for p in config_dir.iterdir() if p.is_dir()):
            try:
                run_number = int(run_dir.name)
            except ValueError:
                continue
            status = "completed"
            marker = run_dir / "status.json"
            if marker.is_file():
                try:
                    status = str(json.loads(marker.read_text(encoding="utf-8")).get("status"))
                except (OSError, json.JSONDecodeError, AttributeError):
                    status = "partial"
            rows = load_run(run_dir, config, run_number)
            result = match(rows, gt, eq)
            runs_out.append(
                {
                    "run": run_number,
                    "status": status,
                    "stage": rows[0].stage if rows else "baseline",
                    "overall": confusion(result).as_dict(),
                    "per_cwe": {cwe: value.as_dict() for cwe, value in by_cwe(result).items()},
                    "cvss": cvss_error(result),
                    "rows": len(rows),
                }
            )
        per_config[config] = {"runs": runs_out}
    return per_config


def _aggregate(runs: list[dict[str, Any]], key: str) -> dict[str, Any]:
    complete = [run for run in runs if run["status"] != "partial"]
    partial = [run for run in runs if run["status"] == "partial"]
    aggregated: dict[str, Any] = {}
    for metric in ("precision", "recall", "f1", "fpr"):
        aggregated[metric] = summarise([float(run["overall"][metric]) for run in complete])
    aggregated["partial_runs"] = [run["run"] for run in partial]
    aggregated["tp_total"] = sum(int(run["overall"]["tp"]) for run in complete)
    aggregated[key] = len(complete)
    return aggregated


def evaluate(gt_path: Path, eq_path: Path, runs: Path, out: Path) -> dict[str, Path]:
    """Write every metrics file, the Markdown tables and the chart CSVs."""
    gt = load_gt(gt_path)
    eq = load_equivalence(eq_path)
    data = load_dataset(runs, gt, eq)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    metrics: dict[str, Any] = {"configs": {}}
    for config, payload in data.items():
        metrics["configs"][config] = {
            "aggregate": _aggregate(payload["runs"], "completed_runs"),
            "runs": payload["runs"],
        }
    written["metrics"] = _write(out / "metrics.json", metrics)

    cvss = {
        config: payload["runs"][-1]["cvss"] for config, payload in data.items() if payload["runs"]
    }
    written["cvss"] = _write(out / "cvss.json", cvss)

    charts = out / "charts"
    charts.mkdir(exist_ok=True)
    for name in ("precision_recall", "cost_per_tp", "cvss_error"):
        rows = ["config,value,metric"]
        if name == "cvss_error":
            rows += [f"{c},{v['mean_error']},mean_error" for c, v in cvss.items()]
        else:
            for config, payload in data.items():
                aggregate = metrics["configs"][config]["aggregate"]
                for metric in ("precision", "recall", "f1"):
                    if name == "precision_recall":
                        rows.append(f"{config},{aggregate[metric]['mean']},{metric}")
        written[f"charts/{name}"] = charts / f"{name}.csv"
        (charts / f"{name}.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")

    written["tables"] = _tables(out / "tables.md", metrics)
    return written


def _write(path: Path, payload: Any) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _tables(path: Path, metrics: dict[str, Any]) -> Path:
    lines = [
        "# Experiment results",
        "",
        "Every value is computed by `vulnscan.experiment.evaluate` from the run rows and the ground truth.",
        "",
        "| Config | TP | FP | FN | TN | Precision | Recall | F1 | FPR | Runs | Partial |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for config in CONFIGS:
        entry = metrics["configs"].get(config)
        if entry is None:
            continue
        aggregate = entry["aggregate"]
        runs = entry["runs"]
        totals = {
            key: sum(int(run["overall"][key]) for run in runs if run["status"] != "partial")
            for key in ("tp", "fp", "fn", "tn")
        }
        lines.append(
            "| {c} | {tp} | {fp} | {fn} | {tn} | {p:.3f} | {r:.3f} | {f:.3f} | {fpr:.3f} | {n} | {part} |".format(
                c=config,
                tp=totals["tp"],
                fp=totals["fp"],
                fn=totals["fn"],
                tn=totals["tn"],
                p=aggregate["precision"]["mean"],
                r=aggregate["recall"]["mean"],
                f=aggregate["f1"]["mean"],
                fpr=aggregate["fpr"]["mean"],
                n=aggregate["completed_runs"],
                part=", ".join(str(run) for run in aggregate["partial_runs"]) or "-",
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _cost_rows(runs: Path) -> dict[str, dict[str, float]]:
    """Read optional ``cost.json`` files written by a run or the caller."""
    costs: dict[str, list[dict[str, float]]] = {}
    for path in sorted(runs.glob("*/**/cost.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        config = path.relative_to(runs).parts[0]
        costs.setdefault(config, []).append(
            {
                "tokens": float(payload.get("tokens", 0)),
                "usd": float(payload.get("usd", 0.0)),
                "seconds": float(payload.get("seconds", 0.0)),
            }
        )
    return {
        config: {
            "tokens": statistics.fmean(item["tokens"] for item in items),
            "usd": statistics.fmean(item["usd"] for item in items),
            "seconds": statistics.fmean(item["seconds"] for item in items),
        }
        for config, items in costs.items()
    }


def cost_metrics(runs: Path, metrics: dict[str, Any]) -> dict[str, Any]:
    """Cost per configuration and per true positive; zero TP reports null."""
    out: dict[str, Any] = {}
    for config, cost in _cost_rows(runs).items():
        entry = metrics["configs"].get(config, {})
        tp = int(entry.get("aggregate", {}).get("tp_total", 0))
        out[config] = {
            **{key: round(value, 4) for key, value in cost.items()},
            "tp": tp,
            "tokens_per_tp": round(cost["tokens"] / tp, 4) if tp else None,
            "usd_per_tp": round(cost["usd"] / tp, 4) if tp else None,
        }
    return out


def human_metrics(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    """Gate counts and seconds per gate, from logged decision timestamps."""
    per_gate: dict[str, list[float]] = {}
    for event in decisions:
        gate = str(event.get("gate"))
        seconds = event.get("seconds")
        if isinstance(seconds, (int, float)):
            per_gate.setdefault(gate, []).append(float(seconds))
    return {
        "decisions": len(decisions),
        "per_gate": {
            gate: {"count": len(values), "mean_seconds": round(statistics.fmean(values), 3)}
            for gate, values in per_gate.items()
        },
    }


def laya_effect(metrics: dict[str, Any], costs: dict[str, Any]) -> dict[str, Any]:
    """S2 against S1: what Laya cost and what recall it changed."""
    s1, s2 = metrics["configs"].get("S1"), metrics["configs"].get("S2")
    if not s1 or not s2:
        return {"available": False, "reason": "S1 or S2 missing"}
    return {
        "available": True,
        "recall_delta": round(
            s2["aggregate"]["recall"]["mean"] - s1["aggregate"]["recall"]["mean"], 4
        ),
        "precision_delta": round(
            s2["aggregate"]["precision"]["mean"] - s1["aggregate"]["precision"]["mean"], 4
        ),
        "usd_s1": costs.get("S1", {}).get("usd"),
        "usd_s2": costs.get("S2", {}).get("usd"),
        "seconds_s1": costs.get("S1", {}).get("seconds"),
        "seconds_s2": costs.get("S2", {}).get("seconds"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score the experiment runs against the ground truth"
    )
    parser.add_argument("--gt", required=True, type=Path)
    parser.add_argument("--eq", required=True, type=Path)
    parser.add_argument("--runs", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    written = evaluate(args.gt, args.eq, args.runs, args.out)
    metrics = json.loads(written["metrics"].read_text(encoding="utf-8"))
    costs = cost_metrics(args.runs, metrics)
    decisions: list[dict[str, Any]] = []
    for path in sorted(args.runs.glob("*/**/decisions.json")):
        try:
            decisions.extend(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    _write(args.out / "cost.json", costs)
    _write(args.out / "human.json", human_metrics(decisions))
    _write(args.out / "laya.json", laya_effect(metrics, costs))
    print(f"wrote {len(written) + 3} files under {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
