"""FR-50/53: EXE -> real provider parser -> deterministic score -> retained proposal."""

import json
from pathlib import Path

import pytest

from tests.platform.test_native_ai import BINARY, native_ai
from tests.platform.test_scan_service import checkout
from vulnscan.core.scan_service import ScanService

__all__ = ["checkout"]
pytestmark = pytest.mark.skipif(not BINARY.is_file(), reason="Build native binary first")


def test_native_ai_scores_vector_but_cannot_confirm_without_independent_proof(
    checkout, tmp_path, monkeypatch
):
    monkeypatch.setenv("DEVSECOPS_FIXTURE_CVSS", "1")
    db = tmp_path / "cvss.db"
    result = native_ai(
        "scan-run",
        "--checkout",
        str(checkout),
        "--db-path",
        str(db),
        "--out",
        str(tmp_path / "reports"),
        "--ai-review",
        "--provider",
        "offline-native",
        "--json",
    )
    assert result.returncode == 0, result.stderr + result.stdout[-2000:]
    summary = json.loads(result.stdout)
    assessment = summary["assessments"][0]
    assert assessment["cvss"]["base_score"] == 9.3
    assert assessment["cvss"]["metric_assumptions_verified"] is False
    assert assessment["assumptions"] == ["Fixture assumption requires independent verification"]
    assert summary["validation_decisions"][0]["new_status"] == "unresolved"
    finding = ScanService(str(db)).finding(summary["id"], assessment["finding_id"])
    assert finding["status"] == "unresolved"
    assert (
        finding["metadata"]["ai_assessments"][0]["cvss"]["calculation_source"] == "FIRST CVSS v4.0"
    )
    exported = json.loads(Path(summary["reports"]["json"]).read_text(encoding="utf-8"))
    assert exported["findings"][0]["metadata"]["ai_assessments"][0]["cvss"]["base_score"] == 9.3
