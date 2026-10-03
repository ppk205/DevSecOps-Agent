"""QR-21 / FR-70: native cancellation and cross-process exclusion."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.platform.test_native import BINARY, native
from tests.platform.test_scan_service import checkout
from vulnscan.core.scan_service import ScanService

__all__ = ["checkout"]
pytestmark = pytest.mark.skipif(
    not BINARY.is_file(), reason="build Go before native cancellation tests"
)


def test_native_cancel_preserves_partial_evidence_and_excludes_second_run(checkout, tmp_path):
    path = tmp_path / "native-cancel.db"
    env = {
        **os.environ,
        "DEVSECOPS_PYTHON": sys.executable,
        "DEVSECOPS_RPC_MODULE": "tests.platform.rpc_fixture",
        "DEVSECOPS_FIXTURE_SLOW": "1",
    }
    process = subprocess.Popen(
        [
            str(BINARY),
            "scan-run",
            "--checkout",
            str(checkout),
            "--db-path",
            str(path),
            "--out",
            str(tmp_path / "slow-reports"),
            "--json",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    try:
        observed = None
        for _ in range(150):
            if path.exists():
                candidate = ScanService(str(path))
                history = candidate.history()
                if history and candidate.finding_page(history[0]["id"])["total"]:
                    observed = candidate
                    break
            time.sleep(0.05)
        assert observed is not None, "Native scanner did not persist partial findings"
        run_id = observed.history()[0]["id"]
        contender = native(
            "scan-run",
            "--checkout",
            str(checkout),
            "--db-path",
            str(path),
            "--out",
            str(tmp_path / "contender-reports"),
            "--json",
        )
        assert contender.returncode == 2
        assert "another scan is active" in contender.stdout
        assert len(observed.history()) == 1
        observed.cancel(run_id)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 130, stderr + stdout
        result = json.loads(stdout)
        assert result["status"] == "cancelled" and result["findings"] == 1
        assert Path(result["summary_path"]).is_file()
        assert Path(result["reports"]["json"]).is_file()
        assert observed.detail(run_id)["findings"]
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        for stream in (process.stdout, process.stderr):
            if stream:
                stream.close()
