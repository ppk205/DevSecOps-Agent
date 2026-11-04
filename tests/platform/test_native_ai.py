"""FR-48/49/71: EXE -> JSONL -> Python AI -> persisted model explanations."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.platform.test_scan_service import checkout
from vulnscan.core.scan_service import ScanService

__all__ = ["checkout"]
ROOT = Path(__file__).parents[2]
BINARY = ROOT / "bin" / ("devsecops-agent-go.exe" if os.name == "nt" else "devsecops-agent-go")
pytestmark = pytest.mark.skipif(not BINARY.is_file(), reason="build the native binary first")


def native_ai(*args, unavailable=False, failed=False):
    env = {
        **os.environ,
        "DEVSECOPS_PYTHON": sys.executable,
        "DEVSECOPS_NATIVE": "python",
        "DEVSECOPS_RPC_MODULE": "tests.platform.ai_rpc_fixture",
    }
    if unavailable:
        env["DEVSECOPS_FIXTURE_AI_UNAVAILABLE"] = "1"
    if failed:
        env["DEVSECOPS_FIXTURE_AI_FAIL"] = "1"
    return subprocess.run(
        [str(BINARY), *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize("mode", ["review", "hunt"])
def test_fr48_exe_runs_real_ai_wiring_and_preserves_explanations(checkout, tmp_path, mode):
    db = tmp_path / "ai.db"
    flags = ["--ai-review", "--ai-report"] if mode == "review" else ["--mode", "hunt"]
    result = native_ai(
        "scan-run",
        "--checkout",
        str(checkout),
        "--db-path",
        str(db),
        "--out",
        str(tmp_path / "reports"),
        "--provider",
        "offline-native",
        "--model",
        "selected-fixture-model",
        *flags,
        "--json",
    )
    assert result.returncode == 0, result.stderr + result.stdout[-4000:]
    summary = json.loads(result.stdout)
    assert summary["assessments"]
    assert "Fixture explanation" in summary["assessments"][0]["rationale"]
    assert summary["model_calls"]
    assert all(call["model"] == "selected-fixture-model" for call in summary["model_calls"])
    assert summary["ai_usage"]["total_tokens"] == len(summary["model_calls"]) * 12
    assert summary["ai_usage"]["cost_usd"] is None
    assert summary["final_report"]["ai_written"] is True
    assert all(d["decided_by"] == "independent-validator" for d in summary["validation_decisions"])
    assert any(event["stage"] == "model_tool" for event in summary["stages"])
    assert any("Fixture explanation" in event["message"] for event in summary["stages"])
    service = ScanService(str(db))
    finding_id = summary["assessments"][0]["finding_id"]
    card = service.finding(summary["id"], finding_id)
    assert card["metadata"]["ai_assessments"][0]["rationale"]
    assert service.activity(summary["id"])["result"]["ai_usage"]["total_tokens"] > 0
    retried = native_ai("scan-retry", summary["run_id"], "--db-path", str(db), "--json")
    assert retried.returncode == 0, retried.stderr + retried.stdout[-4000:]
    next_run = json.loads(retried.stdout)
    assert next_run["run_id"] != summary["run_id"]
    assert next_run["assessments"] and next_run["model_calls"]


def test_fr48_unavailable_provider_is_skipped_without_fake_usage(checkout, tmp_path):
    result = native_ai(
        "scan-run",
        "--checkout",
        str(checkout),
        "--db-path",
        str(tmp_path / "missing.db"),
        "--out",
        str(tmp_path / "reports"),
        "--mode",
        "hunt",
        "--json",
        unavailable=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout[-4000:]
    summary = json.loads(result.stdout)
    assert summary["model_calls"] == [] and summary["assessments"] == []
    assert summary["ai_usage"]["total_tokens"] is None
    assert (
        next(s for s in summary["stages"] if s["stage"] == "targeted_deep_analysis")["status"]
        == "skipped"
    )


def test_fr48_provider_failure_retains_baselines_and_failed_call_status(checkout, tmp_path):
    result = native_ai(
        "scan-run",
        "--checkout",
        str(checkout),
        "--db-path",
        str(tmp_path / "failed.db"),
        "--out",
        str(tmp_path / "reports"),
        "--ai-review",
        "--provider",
        "offline-native",
        "--json",
        failed=True,
    )
    assert result.returncode == 0, result.stderr + result.stdout[-4000:]
    summary = json.loads(result.stdout)
    assert summary["findings"] > 0
    assert summary["model_calls"] and all(c["status"] == "failed" for c in summary["model_calls"])
    assert summary["ai_usage"]["total_tokens"] is None


def test_fr48_native_default_does_not_call_models_even_with_a_keyed_profile(checkout, tmp_path):
    result = native_ai(
        "scan-run",
        "--checkout",
        str(checkout),
        "--db-path",
        str(tmp_path / "off.db"),
        "--out",
        str(tmp_path / "reports"),
        "--json",
    )
    assert result.returncode == 0, result.stderr + result.stdout[-4000:]
    summary = json.loads(result.stdout)
    assert not summary.get("model_calls") and not summary.get("assessments")
    assert (
        next(s for s in summary["stages"] if s["stage"] == "targeted_deep_analysis")["status"]
        == "skipped"
    )
