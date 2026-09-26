"""Benchmark the local Laya model on the target GPU.

Reports cold load, warm inference, batch throughput, and peak memory. Run it
after installing the optional dependency:

    python scripts/laya_bench.py --device auto

Every measurement is printed as JSON so a run can be pasted into the T09
experiment log verbatim. Nothing here touches the production pipeline.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from typing import Any

QUESTIONS = {
    "recommended_action": {
        "type": "choice",
        "instructions": "You triage a normalized static-analysis finding. Choose the next analysis step.",
        "criteria": {
            "fast_verification": "A single targeted run settles it.",
            "cross_file_analysis": "Taint crosses files.",
            "authorization_analysis": "Role or permission checks matter.",
            "human_review": "Ambiguous, a human decides.",
        },
    },
    "evidence_sufficiency": {
        "type": "score",
        "instructions": "How sufficient is current evidence? 0 insufficient, 2 sufficient.",
        "criteria": ["insufficient", "partial", "sufficient"],
    },
    "needs_human_review": {
        "type": "noul",
        "instructions": "Does a human reviewer need to decide this finding?",
    },
}

STATES = [
    {
        "finding_id": "F-1",
        "cwe_category": "CWE-89",
        "severity": "high",
        "file_path": "src/main/java/com/jva/bookstore/dao/Dao.java",
        "line_start": 42,
        "has_dataflow": True,
    },
    {
        "finding_id": "F-2",
        "cwe_category": "CWE-862",
        "severity": "medium",
        "file_path": "src/main/java/com/jva/bookstore/web/AdminServlet.java",
        "line_start": 88,
        "has_dataflow": False,
    },
    {
        "finding_id": "F-3",
        "cwe_category": "CWE-79",
        "severity": "high",
        "file_path": "src/main/webapp/product.jsp",
        "line_start": 12,
        "jsp_context": True,
    },
    {
        "finding_id": "F-4",
        "cwe_category": "CWE-798",
        "severity": "critical",
        "file_path": "src/main/java/com/jva/bookstore/config/Keys.java",
        "line_start": 7,
    },
]


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    index = min(round((pct / 100) * (len(ordered) - 1)), len(ordered) - 1)
    return round(ordered[index], 2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark Laya locally")
    parser.add_argument("--model", default="convaiinnovations/laya")
    parser.add_argument("--device", default="auto", help="auto|cuda|cpu")
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--batch-sizes", default="1,4")
    parser.add_argument("--max-len", type=int, default=512)
    args = parser.parse_args()

    report: dict[str, Any] = {
        "model": args.model,
        "requested_device": args.device,
        "python": platform.python_version(),
        "platform": platform.platform(),
    }

    try:
        import torch
    except ImportError as exc:
        report.update(status="torch_missing", error=str(exc))
        print(json.dumps(report, indent=2))
        return 1

    report["torch"] = torch.__version__
    report["cuda_available"] = torch.cuda.is_available()
    report["cuda_device_name"] = (
        torch.cuda.get_device_name(0) if torch.cuda.is_available() else None
    )
    report["cuda_total_mib"] = (
        round(torch.cuda.get_device_properties(0).total_memory / 1024**2)
        if torch.cuda.is_available()
        else None
    )

    try:
        import laya
    except ImportError as exc:
        report.update(status="laya_missing", error=str(exc))
        print(json.dumps(report, indent=2))
        return 1

    report["laya_version"] = getattr(laya, "__version__", "unknown")

    device = None if args.device == "auto" else args.device
    started = time.perf_counter()
    try:
        agent = laya.load(args.model, device=device)
    except Exception as exc:  # noqa: BLE001 - a benchmark reports any load failure
        report.update(
            status="model_load_failed",
            load_ms=round((time.perf_counter() - started) * 1000, 1),
            error=f"{type(exc).__name__}: {exc}",
        )
        print(json.dumps(report, indent=2))
        return 1

    report["status"] = "model_loaded"
    report["load_ms"] = round((time.perf_counter() - started) * 1000, 1)
    report["resolved_device"] = str(getattr(agent, "device", "unknown"))

    def _reset_peak() -> None:
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()

    def _peak_mib() -> float | None:
        if not torch.cuda.is_available():
            return None
        return round(torch.cuda.max_memory_allocated() / 1024**2, 1)

    # ---- warmup ------------------------------------------------------- #
    for state in STATES[: args.warmup]:
        try:
            agent.predict(state, QUESTIONS, max_len=args.max_len)
        except TypeError:
            agent.predict(state, QUESTIONS)

    # ---- single-state latency ---------------------------------------- #
    _reset_peak()
    single_ms: list[float] = []
    for index in range(args.iterations):
        state = STATES[index % len(STATES)]
        t0 = time.perf_counter()
        try:
            agent.predict(state, QUESTIONS, max_len=args.max_len)
        except TypeError:
            agent.predict(state, QUESTIONS)
        single_ms.append((time.perf_counter() - t0) * 1000)

    report["single_state"] = {
        "iterations": len(single_ms),
        "p50_ms": round(statistics.median(single_ms), 2),
        "p95_ms": _percentile(single_ms, 95),
        "mean_ms": round(statistics.fmean(single_ms), 2),
        "peak_gpu_mib": _peak_mib(),
    }

    # ---- sample output shape ------------------------------------------ #
    try:
        sample = agent.predict(STATES[0], QUESTIONS, max_len=args.max_len)
        report["sample_output"] = _summarise(sample)
    except Exception as exc:  # noqa: BLE001 - shape capture must not abort the run
        report["sample_output_error"] = f"{type(exc).__name__}: {exc}"

    # ---- batch throughput -------------------------------------------- #
    has_batch = callable(getattr(agent, "predict_batch", None))
    report["has_predict_batch"] = has_batch
    if has_batch:
        batches = {}
        for raw_size in args.batch_sizes.split(","):
            size = int(raw_size)
            states = [dict(s, finding_id=f"{s['finding_id']}-{size}") for s in STATES[:size]]
            if not states:
                continue
            _reset_peak()
            t0 = time.perf_counter()
            try:
                out = agent.predict_batch(states, QUESTIONS, max_len=args.max_len)
            except Exception as exc:  # noqa: BLE001 - record the batch error, keep going
                batches[str(size)] = {"error": f"{type(exc).__name__}: {exc}"}
                continue
            elapsed = (time.perf_counter() - t0) * 1000
            count = len(out) if isinstance(out, list) else 1
            batches[str(size)] = {
                "states": len(states),
                "results": count,
                "total_ms": round(elapsed, 2),
                "ms_per_state": round(elapsed / max(count, 1), 2),
                "peak_gpu_mib": _peak_mib(),
            }
        report["batches"] = batches

    print(json.dumps(report, indent=2))
    return 0


def _summarise(raw: Any) -> Any:
    """Compact the native answer shape so the log stays readable."""
    if not isinstance(raw, dict):
        return str(type(raw).__name__)
    answers = raw.get("answers")
    if not isinstance(answers, dict):
        return sorted(raw.keys())
    out: dict[str, Any] = {}
    for name, value in answers.items():
        if isinstance(value, dict):
            out[name] = {
                k: value[k]
                for k in ("type", "choice", "score", "noul", "confidence")
                if k in value
            }
            if "probabilities" in value and isinstance(value["probabilities"], dict):
                out[name]["probabilities"] = {
                    k: round(float(v), 4) for k, v in value["probabilities"].items()
                }
        else:
            out[name] = str(value)
    return out


if __name__ == "__main__":
    raise SystemExit(main())
