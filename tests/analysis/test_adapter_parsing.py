"""T02 gate: scanner adapter parsing of recorded fixtures (no binaries needed)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestSemgrepParsing:
    def test_parses_legacy_json(self) -> None:
        from vulnscan.scanners.semgrep_adapter import parse_json

        obs, coverage = parse_json(
            _load("semgrep_sample.json"),
            run_id="test-run-1",
            tool_version="1.70.0",
            source_snapshot="src/main/java",
        )
        assert len(obs) == 1
        o = obs[0]
        assert o.cwe_category.value == "CWE-89"
        assert o.location.file_path.endswith("UserDAO.java")
        assert o.location.line_start == 42
        assert o.rule_id == "java.lang.security.audit.sql-injection"


class TestDependencyCheckParsing:
    def test_parses_dependency_track(self) -> None:
        text = _load("depcheck_sample.json")
        data = json.loads(text)

        assert "results" in data
        results = data["results"]
        assert results and "vulnerabilities" in results[0]

        vulns = results[0]["vulnerabilities"]
        assert vulns[0]["name"] == "org.postgresql:postgresql"


class TestInvalidCweRejected:
    def test_normalizer_drops_empty_file_path(self) -> None:
        """An observation with an empty file_path is dropped by the normalizer."""
        from vulnscan.contracts import CWECategory, Observation, ScannerResult
        from vulnscan.contracts.finding import SourceCoordinate
        from vulnscan.normalization import normalize_result

        now = datetime.now(timezone.utc)
        good = Observation(
            observation_id="o1",
            detected_at=now,
            run_id="r1",
            tool="semgrep",
            tool_version="1.0",
            rule_id="r1",
            cwe_category=CWECategory.SQL_INJECTION,
            severity="high",
            message="x",
            confidence=1.0,
            location=SourceCoordinate(file_path="A.java", line_start=1),
        )
        bad_file = Observation(
            observation_id="o2",
            detected_at=now,
            run_id="r1",
            tool="semgrep",
            tool_version="1.0",
            rule_id="r2",
            cwe_category=CWECategory.SQL_INJECTION,
            severity="high",
            message="x",
            confidence=1.0,
            location=SourceCoordinate(file_path="", line_start=1),
        )
        result = ScannerResult(
            run_id="r1",
            tool="semgrep",
            tool_version="1.0",
            adapter_version="0.1.0",
            status="completed",
            started_at=now,
            observations=[good, bad_file],
        )
        norm = normalize_result(result)
        assert len(norm) == 1
        assert norm[0].observation_id == "o1"
