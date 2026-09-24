"""Compatibility spike for the optional local Laya backend.

This script is intentionally outside the production pipeline. It verifies the
installed package API without making the core scanner depend on Laya.
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify local Laya package/API compatibility")
    parser.add_argument("--model", default="convaiinnovations/laya")
    parser.add_argument("--device", default="auto")
    parser.add_argument("--load", action="store_true", help="download/load the model; omit for API-only check")
    args = parser.parse_args()

    try:
        import laya
    except ImportError as exc:
        print(json.dumps({"status": "unavailable", "error": str(exc)}))
        return 0

    result: dict[str, Any] = {
        "status": "api_verified",
        "package_version": getattr(laya, "__version__", None),
        "model": args.model,
        "device": args.device,
        "has_load": callable(getattr(laya, "load", None)),
    }
    if args.load:
        started = time.perf_counter()
        try:
            agent = laya.load(args.model, device=None if args.device == "auto" else args.device)
            result.update(
                {
                    "status": "model_loaded",
                    "load_ms": round((time.perf_counter() - started) * 1000, 2),
                    "agent_type": type(agent).__name__,
                    "agent_model_id": getattr(agent, "model_id", None),
                    "agent_device": str(getattr(agent, "device", "unknown")),
                    "has_predict": callable(getattr(agent, "predict", None)),
                    "has_system_one": callable(getattr(agent, "system_one", None)),
                    "has_predict_batch": callable(getattr(agent, "predict_batch", None)),
                }
            )
        except Exception as exc:  # noqa: BLE001 - spike reports the real environment result
            result.update({"status": "model_load_failed", "error": f"{type(exc).__name__}: {exc}"})
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
