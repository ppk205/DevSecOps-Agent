"""Deterministic experiment tables from frozen artifacts and agreed labels.

Missing measurements are null. Partial, failed and skipped runs are retained
but excluded from means. Proposed and after-G5 stages are scored independently.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from dataclasses import dataclass, replace
from datetime import datetime
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
from vulnscan.experiment.normalize import SCANNERS, from_b6, from_harness, from_sarif, from_scan_run
from vulnscan.harness.evidence import score_cvss4
from vulnscan.providers.credentials import redact, redact_value

CONFIGS = ("B1", "B2", "B3", "B4", "B5", "B6", "B7", "S1", "S2", "S3", "F1", "F2", "F3", "F4", "R1")
STAGES = ("baseline", "proposed", "after_g5")
METRICS = ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr")


def _ratio(numerator: float | None, denominator: float | None) -> float | None:
    return round(numerator / denominator, 4) if numerator is not None and denominator else None


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        denominator = 2 * self.tp + self.fp + self.fn
        return 2 * self.tp / denominator if denominator else None

    @property
    def fpr(self) -> float | None:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else None

    def as_dict(self) -> dict[str, float | int | None]:
        return {
            key: round(value, 4) if isinstance(value := getattr(self, key), float) else value
            for key in METRICS
        }


def confusion(result: MatchResult) -> Confusion:
    return Confusion(len(result.tp), len(result.fp), len(result.fn), len(result.tn))


def by_cwe(result: MatchResult) -> dict[str, Confusion]:
    table: dict[str, Confusion] = {}
    for _, item in result.tp:
        table.setdefault(item.cwe, Confusion()).tp += 1
    for row in result.fp:
        table.setdefault(row.cwe, Confusion()).fp += 1
    for item in result.fn:
        table.setdefault(item.cwe, Confusion()).fn += 1
    for item in result.tn:
        table.setdefault(item.cwe, Confusion()).tn += 1
    return table


def cvss_error(result: MatchResult) -> dict[str, Any]:
    errors: list[float] = []
    exact = invalid = missing = 0
    for row, item in result.tp:
        if not row.cvss_vector or not item.cvss_vector:
            missing += 1
            continue
        try:
            errors.append(abs(score_cvss4(row.cvss_vector) - score_cvss4(item.cvss_vector)))
        except ValueError:
            invalid += 1
            continue
        exact += row.cvss_vector.strip() == item.cvss_vector.strip()
    return {
        "pairs": len(errors),
        "missing_pairs": missing,
        "invalid_pairs": invalid,
        "mean_error": round(statistics.fmean(errors), 4) if errors else None,
        "max_error": round(max(errors), 4) if errors else None,
        "exact_share": _ratio(exact, len(errors)),
    }


def summarise(values: list[float | None]) -> dict[str, Any]:
    known = [value for value in values if value is not None and math.isfinite(value)]
    return {
        "mean": round(statistics.fmean(known), 4) if known else None,
        "min": round(min(known), 4) if known else None,
        "max": round(max(known), 4) if known else None,
        "runs": len(known),
    }


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise TypeError("expected JSON object")
            events.append(event)
        except (ValueError, TypeError):
            events.append({"type": "error", "error": "invalid JSONL record"})
    return events


def _run_dirs(runs: Path) -> list[tuple[str, int, Path]]:
    return [
        (config.name, int(run.name), run)
        for config in sorted(runs.iterdir())
        if config.is_dir() and config.name in CONFIGS
        for run in sorted(config.iterdir())
        if run.is_dir() and run.name.isdigit()
    ]


def load_run(rows_dir: Path, config: str, run: int) -> list[Row]:
    """One source per slot; rebind external single-run formats to the slot number."""
    if (rows_dir / "report.json").is_file():
        rows = from_harness(rows_dir / "report.json", rows_dir / "session.jsonl", config, run)
    elif config == "B6":
        rows = from_b6(rows_dir / "b6.jsonl", config, run)
    elif config == "B3":
        rows = from_sarif(rows_dir / "codeql.sarif", config)
    else:
        rows = from_scan_run(rows_dir, config)
    return [replace(row, run=run) for row in rows]


def _status(path: Path, config: str) -> tuple[str, str]:
    marker = _json(path / "status.json")
    stated = marker.get("status")
    if stated in {"partial", "failed", "skipped", "unavailable"}:
        return str(stated), str(marker.get("reason", ""))
    if (path / "status.json").exists() and stated != "completed":
        return "partial", "invalid status marker"
    events = _events(path / ("b6.jsonl" if config == "B6" else "session.jsonl"))
    if any(event.get("type") == "error" for event in events):
        return "partial", "error event in run log"
    if config == "B6":
        end = next((event for event in reversed(events) if event.get("type") == "run_end"), {})
        if end.get("status") != "completed":
            return "partial", str(end.get("reason", "missing completed B6 run_end"))
        return "completed", ""
    artifact = path / (
        f"scanner-{SCANNERS[config]}.json"
        if config in SCANNERS
        else "codeql.sarif"
        if config == "B3"
        else "hunt.json"
        if config == "B7"
        else "report.json"
    )
    if (path / "report.json").is_file():
        artifact = path / "report.json"
    payload = _json(artifact)
    if not payload:
        return "partial", f"missing or invalid {artifact.name}"
    if artifact.name.startswith("scanner-"):
        observations = payload.get("observations")
        if not isinstance(observations, list) or len(from_scan_run(path, config)) != len(
            observations
        ):
            return "partial", "scanner observations contain unnormalisable locations"
    if artifact.name == "report.json":
        findings = payload.get("findings")
        if not isinstance(findings, list) or len(
            [
                row
                for row in from_harness(artifact, path / "session.jsonl", config, 1)
                if row.stage == "proposed"
            ]
        ) != len(findings):
            return "partial", "harness proposals contain missing locations"
    if artifact.name == "codeql.sarif":
        sarif_runs = payload.get("runs")
        if not isinstance(sarif_runs, list) or any(
            not isinstance(run, dict) or not isinstance(run.get("results", []), list)
            for run in sarif_runs
        ):
            return "partial", "invalid SARIF run envelope"
        expected = sum(len(run.get("results", [])) for run in sarif_runs)
        if len(from_sarif(artifact, config)) != expected:
            return "partial", "SARIF results contain missing locations"
        if any(
            invocation.get("executionSuccessful") is False
            for run in sarif_runs
            for invocation in run.get("invocations", [])
            if isinstance(invocation, dict)
        ):
            return "partial", "SARIF invocation failed"
    if (
        payload.get("status", "completed") != "completed"
        or payload.get("errors")
        or payload.get("failed_units")
    ):
        return "partial", f"{artifact.name} reports incomplete analysis"
    if config == "B7":
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or len(from_scan_run(path, config)) != len(candidates):
            return "partial", "hunt candidates contain missing locations"
        summary = _json(path / "summary.json")
        if summary.get("errors") or summary.get("status", "completed") != "completed":
            return "partial", "hunt summary reports incomplete analysis"
    return "completed", str(marker.get("reason", ""))


def _score(rows: list[Row], gt: list[GTItem], eq: dict[str, frozenset[str]]) -> dict[str, Any]:
    result = match(rows, gt, eq)
    overall = confusion(result).as_dict()
    safe_cwes = {item.cwe for item in gt if item.agreed and item.kind == "safe"}
    if not safe_cwes:
        overall["fpr"] = None
    per_cwe = {cwe: value.as_dict() for cwe, value in sorted(by_cwe(result).items())}
    for cwe, score in per_cwe.items():
        if cwe not in safe_cwes:
            score["fpr"] = None
    return {
        "overall": overall,
        "per_cwe": per_cwe,
        "cvss": cvss_error(result),
        "rows": len(rows),
        "duplicates": len(result.duplicates),
        "matched_gt_ids": sorted({item.id for _, item in result.tp}),
    }


def load_dataset(runs: Path, gt: list[GTItem], eq: dict[str, frozenset[str]]) -> dict[str, Any]:
    """Read ``<runs>/<config>/<integer>/``; use a separate root per added model."""
    data: dict[str, Any] = {}
    for config, number, path in _run_dirs(runs):
        status, reason = _status(path, config)
        rows = load_run(path, config, number)
        stage_names = ["proposed", "after_g5"] if (path / "report.json").is_file() else ["baseline"]
        metadata = _json(path / "status.json")
        cohort = metadata.get("gt_ids")
        scoped = [item for item in gt if item.id in cohort] if isinstance(cohort, list) else gt
        if config in {"B4", "B5"} and not isinstance(cohort, list):
            status, reason = (
                "partial",
                "B4/B5 require explicit gt_ids for their separate comparison cohort",
            )
        stages = {
            stage: _score([row for row in rows if row.stage == stage], scoped, eq)
            for stage in stage_names
        }
        for score in stages.values():
            score.update(status=status, reason=reason)
        if "after_g5" in stages and status == "completed":
            events = _events(path / "session.jsonl") or _json(path / "report.json").get(
                "decisions", []
            )
            reviewed = {
                str(event.get("payload", {}).get("finding_id"))
                for event in events
                if event.get("type") == "gate"
                and event.get("gate") == "G5"
                and isinstance(event.get("payload"), dict)
                and event.get("choice") in {"confirm", "reject", "need_more"}
            }
            proposals = {row.source_id for row in rows if row.stage == "proposed"}
            if not reviewed:
                stages["after_g5"].update(
                    status="unavailable", reason="no recorded human G5 decisions"
                )
            elif not proposals <= reviewed:
                stages["after_g5"].update(status="partial", reason="human G5 review is incomplete")
        primary = stage_names[0]
        record = {
            "run": number,
            "status": status,
            "reason": reason,
            "stage": primary,
            "stages": stages,
            **stages[primary],
        }
        data.setdefault(config, {"runs": []})["runs"].append(record)
    return data


def _aggregate(runs: list[dict[str, Any]], key: str = "completed_runs") -> dict[str, Any]:
    complete = [run for run in runs if run["status"] == "completed"]
    return {
        **{metric: summarise([run["overall"][metric] for run in complete]) for metric in METRICS},
        "partial_runs": [run["run"] for run in runs if run["status"] == "partial"],
        "excluded_runs": [
            {"run": run["run"], "status": run["status"], "reason": run.get("reason", "")}
            for run in runs
            if run["status"] != "completed"
        ],
        "tp_total": sum(run["overall"]["tp"] for run in complete),
        key: len(complete),
    }


def _number(value: Any) -> float | None:
    return (
        float(value)
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
        else None
    )


def _seconds(start: Any, end: Any) -> float | None:
    try:
        value = (
            datetime.fromisoformat(str(end)) - datetime.fromisoformat(str(start))
        ).total_seconds()
        return value if value >= 0 else None
    except (ValueError, TypeError):
        return None


def _telemetry(path: Path, config: str = "") -> dict[str, float | None]:
    supplied = _json(path / "cost.json")
    if supplied:
        return {key: _number(supplied.get(key)) for key in ("tokens", "usd", "seconds")}
    events = _events(path / "session.jsonl") or _events(path / "b6.jsonl")
    usage = [event for event in events if event.get("type") == "usage"]
    tokens: float | None = 0 if usage else None
    usd: float | None = 0 if usage else None
    for event in usage:
        inp, output = _number(event.get("input_tokens")), _number(event.get("output_tokens"))
        if inp is None or output is None:
            tokens = None
        elif tokens is not None:
            tokens += inp + output
        cost = _number(event.get("cost_usd"))
        # Historical harness transports reported 0 for an unpriced model.
        if cost == 0 and event.get("price_known") is not True:
            cost = None
        usd = usd + cost if usd is not None and cost is not None else None
    timestamps = [event["at"] for event in events if event.get("at")]
    end = next((event for event in reversed(events) if event.get("type") == "run_end"), {})
    duration = _number(end.get("seconds"))
    if duration is None and len(timestamps) >= 2:
        duration = _seconds(timestamps[0], timestamps[-1])
    if duration is None and config in SCANNERS:
        scanner = _json(path / f"scanner-{SCANNERS[config]}.json")
        milliseconds = _number(scanner.get("duration_ms"))
        duration = (
            milliseconds / 1000
            if milliseconds is not None
            else _seconds(scanner.get("started_at"), scanner.get("finished_at"))
        )
    return {"tokens": tokens, "usd": usd, "seconds": duration}


def cost_metrics(runs: Path, metrics: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {config: [] for config in metrics["configs"]}
    for config, number, path in _run_dirs(runs):
        entry = metrics["configs"].get(config, {})
        record: dict[str, Any] = next(
            (item for item in entry.get("runs", []) if item["run"] == number), {}
        )
        status = record.get("status", _json(path / "status.json").get("status", "completed"))
        grouped.setdefault(config, []).append(
            {
                "run": number,
                "status": status,
                **_telemetry(path, config),
                "tp": record.get("overall", {}).get("tp"),
            }
        )
    result: dict[str, Any] = {}
    for config, records in grouped.items():
        complete = [item for item in records if item["status"] == "completed"]
        tp = metrics["configs"].get(config, {}).get("aggregate", {}).get("tp_total", 0)
        stats = {
            key: summarise([item[key] for item in complete]) for key in ("tokens", "usd", "seconds")
        }
        totals = {
            key: sum(item[key] for item in complete)
            if complete and all(item[key] is not None for item in complete)
            else None
            for key in stats
        }
        result[config] = {
            **{key: stats[key]["mean"] for key in stats},
            "tp": tp,
            "runs": records,
            "aggregate": stats,
            "totals": totals,
            **{f"{key}_per_tp": _ratio(total, tp) for key, total in totals.items()},
        }
        for item in records:
            for key in stats:
                item[f"{key}_per_tp"] = _ratio(item[key], item["tp"])
    return result


def human_metrics(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    per_gate: dict[str, list[float | None]] = {}
    requests: dict[str, dict[str, Any]] = {}
    automatic = undecided = 0
    for event in decisions:
        if event.get("type") in {"gate_request", "permission_request"}:
            requests[str(event.get("request_id", event.get("gate")))] = event
            continue
        if event.get("type", "gate") != "gate":
            continue
        if event.get("choice") == "undecided":
            undecided += 1
            continue
        if event.get("person") == "auto":
            automatic += 1
            continue
        if not event.get("person"):
            continue
        gate = str(event.get("gate"))
        seconds = _number(event.get("seconds"))
        if seconds is None:
            request = requests.pop(str(event.get("request_id", gate)), {})
            seconds = _seconds(event.get("requested_at", request.get("at")), event.get("at"))
        per_gate.setdefault(gate, []).append(seconds)
    return {
        "decisions": sum(len(values) for values in per_gate.values()),
        "automatic": automatic,
        "undecided": undecided,
        "per_gate": {
            gate: {
                "count": len(values),
                "mean_seconds": summarise(values)["mean"],
                "timed_count": sum(value is not None for value in values),
            }
            for gate, values in sorted(per_gate.items())
        },
    }


def laya_effect(metrics: dict[str, Any], costs: dict[str, Any]) -> dict[str, Any]:
    s1, s2 = metrics["configs"].get("S1"), metrics["configs"].get("S2")
    if not s1 or not s2:
        return {"available": False, "reason": "S1 or S2 missing"}
    if not s1["aggregate"]["completed_runs"] or not s2["aggregate"]["completed_runs"]:
        return {"available": False, "reason": "S1 or S2 has no completed runs"}

    def delta(left: Any, right: Any) -> float | None:
        return round(right - left, 4) if left is not None and right is not None else None

    out = {
        "available": True,
        "recall_delta": delta(s1["aggregate"]["recall"]["mean"], s2["aggregate"]["recall"]["mean"]),
        "precision_delta": delta(
            s1["aggregate"]["precision"]["mean"], s2["aggregate"]["precision"]["mean"]
        ),
    }
    for key in ("tokens", "usd", "seconds"):
        a, b = costs.get("S1", {}).get(key), costs.get("S2", {}).get(key)
        out[f"{key}_s1"], out[f"{key}_s2"] = a, b
        out[f"{key}_delta"] = delta(a, b)
    return out


def _write(path: Path, payload: Any) -> Path:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(redact_value(payload), indent=2, sort_keys=True) + "\n")
    return path


def evaluate(gt_path: Path, eq_path: Path, runs: Path, out: Path) -> dict[str, Path]:
    """Write all outputs once to a new or empty directory. Never overwrite evidence."""
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"output directory is not empty: {out}")
    gt, eq = load_gt(gt_path), load_equivalence(eq_path)
    data = load_dataset(runs, gt, eq)
    metrics: dict[str, Any] = {
        "configs": {},
        "equivalence": {key: sorted(value) for key, value in sorted(eq.items())},
        "matching_window": 3,
        "agreed_gt_items": sum(item.agreed for item in gt),
    }
    cvss: dict[str, Any] = {}
    for config, payload in data.items():
        records = payload["runs"]
        stage_names = sorted({stage for run in records for stage in run["stages"]})
        stage_aggregates = {}
        for stage in stage_names:
            stage_aggregates[stage] = _aggregate(
                [{**run, **run["stages"][stage]} for run in records if stage in run["stages"]]
            )
        cwes = sorted(
            {cwe for run in records for stage in run["stages"].values() for cwe in stage["per_cwe"]}
        )
        cwe_table: dict[str, Any] = {}
        for cwe in cwes:
            cwe_table[cwe] = {
                stage: _aggregate(
                    [
                        {
                            **run,
                            **run["stages"][stage],
                            "overall": run["stages"][stage]["per_cwe"].get(
                                cwe, Confusion().as_dict()
                            ),
                        }
                        for run in records
                        if stage in run["stages"]
                    ]
                )
                for stage in stage_names
            }
        metrics["configs"][config] = {
            "aggregate": _aggregate(records),
            "runs": records,
            "stages": stage_aggregates,
            "cwes": cwe_table,
        }
        complete = [run for run in records if run["status"] == "completed"]
        cvss[config] = {
            key: summarise([run["cvss"][key] for run in complete])["mean"]
            for key in ("mean_error", "max_error", "exact_share")
        }
        cvss[config]["runs"] = [
            {
                "run": run["run"],
                "status": run["status"],
                "stages": {stage: score["cvss"] for stage, score in run["stages"].items()},
            }
            for run in records
        ]
        cvss[config]["aggregate"] = {
            stage: {
                key: summarise(
                    [
                        run["stages"][stage]["cvss"][key]
                        for run in complete
                        if stage in run["stages"] and run["stages"][stage]["status"] == "completed"
                    ]
                )
                for key in ("mean_error", "max_error", "exact_share")
            }
            for stage in stage_names
        }
    costs = cost_metrics(runs, metrics)
    human: dict[str, Any] = {}
    for config, number, path in _run_dirs(runs):
        events = _events(path / "session.jsonl")
        if not events:
            events = _json(path / "report.json").get("decisions", [])
        effort = (
            human_metrics(events)
            if events
            else {"decisions": None, "automatic": None, "undecided": None, "per_gate": {}}
        )
        human.setdefault(config, []).append({"run": number, **effort, "available": bool(events)})
    out.mkdir(parents=True, exist_ok=True)
    written = {
        name: _write(out / f"{name}.json", value)
        for name, value in {
            "metrics": metrics,
            "cvss": cvss,
            "cost": costs,
            "human": human,
            "laya": laya_effect(metrics, costs),
        }.items()
    }
    written["tables"] = _tables(out / "tables.md", metrics)
    charts = out / "charts"
    charts.mkdir()
    chart_rows: dict[str, list[list[Any]]] = {
        "precision_recall": [],
        "cost_per_tp": [],
        "cvss_error": [],
    }
    for config, entry in metrics["configs"].items():
        for stage, aggregate in entry["stages"].items():
            for metric in ("precision", "recall", "f1", "fpr"):
                summary = aggregate[metric]
                chart_rows["precision_recall"].append(
                    [config, stage, metric, summary["mean"], summary["min"], summary["max"]]
                )
        for metric in ("tokens_per_tp", "usd_per_tp", "seconds_per_tp"):
            chart_rows["cost_per_tp"].append(
                [config, entry["runs"][0]["stage"], metric, costs[config][metric], None, None]
            )
        for stage, aggregate in cvss[config]["aggregate"].items():
            summary = aggregate["mean_error"]
            chart_rows["cvss_error"].append(
                [config, stage, "mean_error", summary["mean"], summary["min"], summary["max"]]
            )
    for name, rows in chart_rows.items():
        path = charts / f"{name}.csv"
        with path.open("x", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(["config", "stage", "metric", "mean", "min", "max"])
            writer.writerows(rows)
        written[f"charts/{name}"] = path
    return written


def _tables(path: Path, metrics: dict[str, Any]) -> Path:
    lines = [
        "# Experiment results",
        "",
        "Values derive from supplied artifacts and agreed labels. Null means unknown or undefined.",
        "Partial and unavailable runs are excluded from means. B4/B5 use separate declared cohorts.",
        "",
        "| Config | Stage | Precision mean [min, max] | Recall mean [min, max] | Completed | Excluded |",
        "|---|---|---|---|---|---|",
    ]
    for config in CONFIGS:
        entry = metrics["configs"].get(config)
        if entry is None:
            lines.append(f"| {config} | unavailable: no run artifacts | — | — | — | — |")
            continue
        for stage, aggregate in entry["stages"].items():
            p, r = aggregate["precision"], aggregate["recall"]
            lines.append(
                f"| {config} | {stage} | {p['mean']} [{p['min']}, {p['max']}] | {r['mean']} [{r['min']}, {r['max']}] | {aggregate['completed_runs']} | {len(aggregate['excluded_runs'])} |"
            )
        for run in entry["runs"]:
            if run["status"] != "completed":
                lines.append(f"\n{config}/{run['run']}: {run['status']}: {run['reason']}")
    lines.extend(["", "## Explicit CWE equivalence", "", "No implicit parent/child matching."])
    lines.extend(f"- {left}: {', '.join(right)}" for left, right in metrics["equivalence"].items())
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(redact("\n".join(lines) + "\n"))
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("gt", "eq", "runs", "out"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        written = evaluate(args.gt, args.eq, args.runs, args.out)
    except (OSError, ValueError) as exc:
        print(redact(str(exc)))
        return 2
    print(f"wrote {len(written)} files under {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
