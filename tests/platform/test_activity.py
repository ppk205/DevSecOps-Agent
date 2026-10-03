"""FR-71/DR-09/IR-16: history exposes its own retained terminal diagnostics."""

import json

from tests.platform.test_scan_service import checkout, service, settings
from vulnscan.storage.database import get_session
from vulnscan.storage.models import RunORM

__all__ = ["checkout", "service"]


def test_dr09_activity_retains_run_scoped_errors_reports_and_count(service, checkout, tmp_path):
    first = service.run(str(checkout), settings(tmp_path))
    service.run(str(checkout), settings(tmp_path))
    with get_session(service.db_path) as session:
        row = session.get(RunORM, first["id"])
        result = json.loads(row.result_json)
        result["errors"] = ["report export failed: disk full"]
        row.result_json = json.dumps(result)
    activity = service.activity(first["run_id"])
    assert activity["result"]["run_id"] == first["run_id"]
    assert activity["result"]["findings"] == first["findings"]
    assert activity["result"]["errors"] == ["report export failed: disk full"]
    assert activity["result"]["reports"] == first["reports"]
    assert all(event["run_id"] == first["run_id"] for event in activity["events"])
    assert "manifest" not in activity["result"] and "observations" not in activity["result"]
