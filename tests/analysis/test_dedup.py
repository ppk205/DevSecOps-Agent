"""T02 gate: dedup preserves contributing observations; never merges by CWE alone."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

_now = datetime.now(timezone.utc)


def _make_finding(
    finding_id: str,
    cwe: str,
    file_path: str = "A.java",
    line_start: int = 10,
    obs_ids: list[str] | None = None,
) -> dict:
    from vulnscan.contracts import CWECategory, EvidenceStrength, Severity

    oid_list = obs_ids or [finding_id]
    observations_list = [
        {
            "observation_id": oid_val,
            "detected_at": _now,
            "run_id": "r1",
            "tool": "semgrep",
            "tool_version": "1.0",
            "rule_id": f"rule-{oid_val}",
            "cwe_category": cwe,
            "severity": Severity.HIGH,
            "message": "x",
            "confidence": 0.9,
            "location": {"file_path": file_path, "line_start": line_start},
        }
        for oid_val in oid_list
    ]
    return {
        "finding_id": finding_id,
        "run_id": "r1",
        "fingerprint": f"fp-{finding_id}",
        "title": f"{cwe} at {file_path}:{line_start}",
        "description": "x",
        "cwe_category": cwe,
        "severity": Severity.HIGH,
        "status": "unprocessed",
        "observations": observations_list,
        "groups": [],
        "evidence_strength": EvidenceStrength.MODERATE,
        "evidence_refs": [],
        "created_at": _now,
        "updated_at": _now,
    }


class TestDeduplication:
    def test_exact_duplicates_removed(self) -> None:
        from vulnscan.contracts import Finding
        from vulnscan.normalization.dedup import deduplicate_findings

        f1 = Finding(**_make_finding("f1", "CWE-89"))
        f2 = Finding(**_make_finding("f2", "CWE-89"))
        # Give them the same fingerprint to make them duplicates.
        f2.fingerprint = f1.fingerprint

        result = deduplicate_findings([f1, f2])
        assert len(result) == 1
        assert result[0].finding_id == "f1"

    def test_same_cwe_different_fingerprints_stay_distinct(self) -> None:
        from vulnscan.contracts import Finding
        from vulnscan.normalization.dedup import deduplicate_findings

        f1 = Finding(**_make_finding("f1", "CWE-89", file_path="A.java", line_start=10))
        f2 = Finding(**_make_finding("f2", "CWE-89", file_path="B.java", line_start=20))

        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_different_cwe_stay_distinct(self) -> None:
        from vulnscan.contracts import Finding
        from vulnscan.normalization.dedup import deduplicate_findings

        f1 = Finding(**_make_finding("f1", "CWE-89"))
        f2 = Finding(**_make_finding("f2", "CWE-79"))

        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_observations_folded_on_dedup(self) -> None:
        from vulnscan.contracts import Finding
        from vulnscan.normalization.dedup import deduplicate_findings

        f1 = Finding(**_make_finding("f1", "CWE-89", obs_ids=["o1", "o2"]))
        f2 = Finding(**_make_finding("f2", "CWE-89", obs_ids=["o3"]))
        f2.fingerprint = f1.fingerprint

        result = deduplicate_findings([f1, f2])
        assert len(result) == 1
        obs_ids = {o.observation_id for o in result[0].observations}
        assert obs_ids == {"o1", "o2", "o3"}
