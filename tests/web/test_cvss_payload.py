"""FR-53: finding API exposes Base and contextual scores without semantic approval."""

import json

from fastapi.testclient import TestClient

from tests.ai.test_review_wiring import _assessment
from tests.platform.test_scan_service import checkout, service, settings
from vulnscan.contracts.assessment import CVSSAssessment
from vulnscan.storage.database import get_engine, get_session
from vulnscan.storage.models import RunORM
from vulnscan.web.app import create_app

__all__ = ["checkout", "service"]


def test_cvss_api_preserves_base_contextual_and_unverified_assumptions(service, checkout, tmp_path):
    summary = service.run(
        str(checkout),
        settings(tmp_path, mode="deterministic", laya=False, tools=["semgrep", "gitleaks"]),
    )
    finding = service.detail(summary["id"])["findings"][0]
    assessment = _assessment()
    assessment.finding_id = finding["finding_id"]
    assessment.cvss = CVSSAssessment(
        vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P"
    )
    with get_session(service.db_path) as session:
        row = session.get(RunORM, summary["id"])
        result = json.loads(row.result_json)
        result["assessments"] = [assessment.model_dump(mode="json")]
        row.result_json = json.dumps(result)
    client = TestClient(create_app(engine=get_engine(service.db_path)))
    result = client.get(f"/api/findings/{finding['finding_id']}", params={"run_id": summary["id"]})
    assert result.status_code == 200
    cvss = result.json()["ai"]["cvss"]
    assert cvss["base_score"] == 9.3 and cvss["overall_score"] == 8.9
    assert cvss["nomenclature"] == "CVSS-BT"
    assert cvss["metric_assumptions_verified"] is False
