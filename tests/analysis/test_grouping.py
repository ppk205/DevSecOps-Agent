"""T02 gate: grouping retains provenance; same-CWE different sites stay distinct."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

_now = datetime.now(timezone.utc)


def _make_obs(file_path: str, line_start: int, cwe: str, rule_id: str) -> dict:
    return {
        "observation_id": f"o-{file_path}-{line_start}",
        "detected_at": _now,
        "run_id": "r1",
        "tool": "semgrep",
        "tool_version": "1.0",
        "rule_id": rule_id,
        "cwe_category": cwe,
        "severity": "high",
        "message": f"at {file_path}:{line_start}",
        "confidence": 0.9,
        "location": {
            "file_path": file_path,
            "language": "java",
            "line_start": line_start,
        },
    }


class TestGroupingPreservesProvenance:
    def test_same_location_cwe_merged(self) -> None:
        from vulnscan.contracts.finding import Observation
        from vulnscan.normalization.grouping import group_findings

        obs1 = Observation(**_make_obs("A.java", 10, "CWE-89", "rule1"))
        obs2 = Observation(**_make_obs("A.java", 10, "CWE-89", "rule2"))

        findings = group_findings([obs1, obs2])
        assert len(findings) == 1
        f = findings[0]
        assert len(f.observations) == 2
        ids = {o.observation_id for o in f.observations}
        assert "o-A.java-10" in ids

    def test_same_cwe_different_sites_stay_distinct(self) -> None:
        from vulnscan.contracts.finding import Observation
        from vulnscan.normalization.grouping import group_findings

        obs1 = Observation(**_make_obs("A.java", 10, "CWE-89", "rule1"))
        obs2 = Observation(**_make_obs("B.java", 20, "CWE-89", "rule1"))

        findings = group_findings([obs1, obs2])
        assert len(findings) == 2

    def test_different_cwe_same_site_stay_distinct(self) -> None:
        from vulnscan.contracts.finding import Observation
        from vulnscan.normalization.grouping import group_findings

        obs1 = Observation(**_make_obs("A.java", 10, "CWE-89", "rule1"))
        obs2 = Observation(**_make_obs("A.java", 10, "CWE-79", "rule2"))

        findings = group_findings([obs1, obs2])
        assert len(findings) == 2
        cwes = {f.cwe_category.value for f in findings}
        assert cwes == {"CWE-89", "CWE-79"}

    def test_multi_tool_evidence_strength(self) -> None:
        from vulnscan.contracts.finding import Observation
        from vulnscan.normalization.grouping import group_findings

        obs1 = Observation(**_make_obs("A.java", 10, "CWE-89", "semgrep-rule"))
        obs2_dict = _make_obs("A.java", 10, "CWE-89", "spotbugs-rule")
        obs2_dict["observation_id"] = "o-A.java-10-spotbugs"
        obs2_dict["tool"] = "spotbugs"
        obs2 = Observation(**obs2_dict)

        findings = group_findings([obs1, obs2])
        assert len(findings) == 1
        assert findings[0].evidence_strength.value == "strong"
