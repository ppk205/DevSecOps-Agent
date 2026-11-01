"""Compare model-hunted vulns vs deterministic scanner findings (pure function)."""

from __future__ import annotations

from datetime import UTC, datetime

from vulnscan.ai.compare import compare_hunt_vs_scanners
from vulnscan.contracts.enums import (
    CWECategory,
    FindingStatus,
    Severity,
    ToolName,
)
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate


def _finding(
    fid: str = "f1",
    file_path: str = "src/LoginServlet.java",
    line: int = 14,
    rule_id: str = "java-sql-concatenation",
    cwe: CWECategory | None = CWECategory.SQL_INJECTION,
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id=fid,
        run_id="r1",
        fingerprint=f"fp-{fid}",
        title=f"finding {fid}",
        description="scanner hit",
        cwe_category=cwe,
        severity=Severity.HIGH,
        status=FindingStatus.UNPROCESSED,
        observations=[
            Observation(
                observation_id=f"obs-{fid}",
                detected_at=now,
                run_id="r1",
                tool=ToolName.SEMGREP,
                tool_version="1.0",
                rule_id=rule_id,
                cwe_category=cwe,
                severity=Severity.HIGH,
                message="hit",
                confidence=0.9,
                location=SourceCoordinate(file_path=file_path, line_start=line),
            )
        ],
        created_at=now,
        updated_at=now,
    )


def _candidate(file: str = "src/LoginServlet.java", line: int = 14, cwe: str = "CWE-89") -> dict:
    return {
        "title": "SQL injection",
        "file": file,
        "line": line,
        "cwe": cwe,
        "severity": "high",
        "rationale": "tainted",
        "evidence": "executeQuery(",
    }


class TestCompare:
    def test_agreed_model_only_scanner_only(self):
        candidates = [
            _candidate(line=16),  # off by 2 from scanner line 14, same CWE -> agreed
            _candidate(file="src/OnlyModel.java", line=5, cwe="CWE-79"),
        ]
        findings = [
            _finding(line=14),
            _finding(
                fid="f2",
                file_path="src/OnlyScanner.java",
                line=50,
                rule_id="java-xss-response-writer",
                cwe=CWECategory.XSS,
            ),
        ]
        out = compare_hunt_vs_scanners(candidates, findings)
        assert len(out["agreed"]) == 1
        assert len(out["model_only"]) == 1
        assert len(out["scanner_only"]) == 1
        assert out["counts"] == {"agreed": 1, "model_only": 1, "scanner_only": 1}

    def test_rule_family_fallback_matches(self):
        # Finding without CWE category still matches via rule->CWE map.
        candidates = [_candidate(line=14)]
        findings = [
            {"file": "src/LoginServlet.java", "line": 14, "rule_id": "java-sql-concatenation"}
        ]
        out = compare_hunt_vs_scanners(candidates, findings)
        assert out["counts"]["agreed"] == 1

    def test_line_tolerance_boundary(self):
        candidates = [_candidate(line=18)]  # 4 lines away -> no match
        findings = [_finding(line=14)]
        out = compare_hunt_vs_scanners(candidates, findings)
        assert out["counts"] == {"agreed": 0, "model_only": 1, "scanner_only": 1}

    def test_empty_inputs(self):
        out = compare_hunt_vs_scanners([], [])
        assert out["counts"] == {"agreed": 0, "model_only": 0, "scanner_only": 0}
