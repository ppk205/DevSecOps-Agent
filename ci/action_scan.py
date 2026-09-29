"""Action transport: the same service and policy used by CLI and TUI."""

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

from vulnscan.core.config import resolve_config
from vulnscan.core.scan_service import ScanService
from vulnscan.core.security import sanitize

root = Path(os.environ["ACTION_ROOT"])
output = Path(
    os.environ["SCAN_OUTPUT"] or str(Path(os.environ["RUNNER_TEMP"]) / "devsecops-reports")
).resolve()
public_id = "run-" + uuid.uuid4().hex
try:
    config = resolve_config(
        os.environ["SCAN_PROFILE"],
        os.environ["SCAN_CONFIG"] or None,
        fail_on=os.environ["SCAN_THRESHOLD"] or None,
        output_dir=str(output),
        ci=True,
        allow_dirty=False,
        laya=False,
    )
    if config.profile == "full":
        subprocess.run([sys.executable, str(root / "ci/build_image.py")], check=True)
    result = ScanService(str(Path(os.environ["RUNNER_TEMP"]) / "devsecops.db")).run(
        os.environ["SCAN_CHECKOUT"], config, public_id=public_id
    )
except Exception as exc:  # noqa: BLE001 - always emit the failure summary
    directory = output / public_id
    directory.mkdir(parents=True, exist_ok=True)
    result = {
        "run_id": public_id,
        "status": "failed",
        "gate": "failed",
        "exit_code": 2,
        "errors": [sanitize(str(exc))],
        "summary_path": str(directory / "summary.json"),
    }
    Path(result["summary_path"]).write_text(json.dumps(result, indent=2), encoding="utf-8")
values = {
    "run-id": result["run_id"],
    "scan-status": result["status"],
    "gate-result": result["gate"],
    "summary-path": result["summary_path"],
    "sarif-path": result.get("reports", {}).get("sarif", ""),
    "exit-code": str(result["exit_code"]),
    "artifact-directory": str(Path(result["summary_path"]).parent),
}
with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
    for key, value in values.items():
        delimiter = uuid.uuid4().hex
        stream.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
    stream.write(
        f"## DevSecOps scan\n\nRun `{public_id}`: **{result['status']}**, gate **{result['gate']}**.\n"
    )
    stream.write(
        f"Exit code: {result['exit_code']}; findings: {result.get('findings', 0)}; unknown severity: {len(result.get('unknown_severity', []))}.\n"
    )
