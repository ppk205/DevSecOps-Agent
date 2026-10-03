"""FR-70/71, DR-09, IR-15: real Go/Python compatibility boundary."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.platform.test_scan_service import checkout, service, settings
from vulnscan.contracts import Finding
from vulnscan.core.scan_service import ScanService
from vulnscan.normalization.grouping import group_findings

__all__ = ["checkout", "service"]
ROOT = Path(__file__).parents[2]
BINARY = ROOT / "bin" / ("devsecops-agent-go.exe" if os.name == "nt" else "devsecops-agent-go")
pytestmark = pytest.mark.skipif(
    not BINARY.is_file(), reason="build the Go binary to run native parity tests"
)


def native(*args, slow=False):
    env = {
        **os.environ,
        "DEVSECOPS_PYTHON": sys.executable,
        "DEVSECOPS_RPC_MODULE": "tests.platform.rpc_fixture",
        "DEVSECOPS_NATIVE": "python",
    }
    if slow:
        env["DEVSECOPS_FIXTURE_SLOW"] = "1"
    return subprocess.run(
        [str(BINARY), *args], env=env, capture_output=True, text=True, timeout=30, check=False
    )


def identity(finding):
    return (
        finding["finding_id"],
        finding["fingerprint"],
        finding["severity"],
        finding["cwe_category"],
        finding["status"],
        finding["evidence_strength"],
        finding["metadata"],
    )


def test_fr70_native_scan_matches_python_findings_policy_and_history(service, checkout, tmp_path):
    baseline = service.run(str(checkout), settings(tmp_path))
    baseline_detail = service.detail(baseline["id"])
    path = tmp_path / "native.db"
    result = native(
        "scan-run",
        "--checkout",
        str(checkout),
        "--db-path",
        str(path),
        "--out",
        str(tmp_path / "go-reports"),
        "--json",
    )
    assert result.returncode == baseline["exit_code"], result.stderr + result.stdout
    actual = json.loads(result.stdout)
    detail = ScanService(str(path)).detail(actual["id"])
    assert [identity(f) for f in detail["findings"]] == [
        identity(f) for f in baseline_detail["findings"]
    ]
    assert actual["gate"] == baseline["gate"]
    assert actual["exceeded"] == baseline["exceeded"]
    assert actual["unknown_severity"] == baseline["unknown_severity"]
    assert actual["manifest"]["files"] == baseline["manifest"]["files"]
    for fmt in baseline["reports"]:
        assert Path(actual["reports"][fmt]).is_file()
    assert [e["stage"] for e in detail["events"]] == [e["stage"] for e in baseline_detail["events"]]
    history = native("scan-list", "--db-path", str(path), "--json")
    assert json.loads(history.stdout)[0]["run_id"] == actual["run_id"]
    retry = native("scan-retry", actual["run_id"], "--db-path", str(path))
    assert retry.returncode == 0, retry.stderr + retry.stdout
    assert ScanService(str(path)).history()[0]["attempt"] == 2


def test_native_group_contract_matches_python(service, checkout, tmp_path):
    result = service.run(str(checkout), settings(tmp_path))
    observations = [o for f in service.detail(result["id"])["findings"] for o in f["observations"]]
    from vulnscan.contracts import Observation

    baseline = group_findings([Observation.model_validate(o) for o in observations], "parity")
    request = {
        "version": 1,
        "id": "group",
        "method": "group",
        "params": {"observations": observations, "run_id": "parity"},
    }
    reply = subprocess.run(
        [str(BINARY), "worker"],
        input=json.dumps(request) + "\n",
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    payload = json.loads(reply.stdout)
    assert payload["ok"], payload
    actual = [Finding.model_validate(f).model_dump(mode="json") for f in payload["result"]]
    assert [identity(f) for f in actual] == [identity(f.model_dump(mode="json")) for f in baseline]
