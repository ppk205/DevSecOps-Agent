"""Unit tests for TrivyAdapter (IaC/Dockerfile/K8s config audit)."""

from __future__ import annotations

from pathlib import Path

from vulnscan.contracts import RunStatus, ScanSpecification, Severity, ToolConfig, ToolName
from vulnscan.scanners.trivy_adapter import TrivyAdapter, parse_trivy_json


def _sample_trivy_report() -> dict:
    return {
        "Results": [
            {
                "Target": "Dockerfile",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "AVDID": "AVD-DS-0002",
                        "Title": "Image user should not be 'root'",
                        "Message": "Specify at least 1 USER command in Dockerfile",
                        "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                        "CauseMetadata": {
                            "StartLine": 1,
                            "EndLine": 3,
                            "Code": {
                                "Lines": [
                                    {"Number": 1, "Content": "FROM python:3.11"},
                                    {"Number": 2, "Content": 'CMD ["python"]'},
                                ]
                            },
                        },
                    },
                    {
                        "ID": "DS001",
                        "AVDID": "AVD-DS-0001",
                        "Title": "Passing rule",
                        "Severity": "LOW",
                        "Status": "PASS",
                    },
                ],
            }
        ]
    }


def test_parse_trivy_json_extracts_failed_misconfigurations() -> None:
    observations, coverage = parse_trivy_json(
        _sample_trivy_report(),
        run_id="r-trivy",
        tool_version="0.58.0",
        source_snapshot="a" * 40,
    )
    assert len(coverage) == 1
    assert coverage[0].unit_path == "Dockerfile"
    assert len(observations) == 1
    obs = observations[0]
    assert obs.tool == ToolName.TRIVY
    assert obs.rule_id == "AVD-DS-0002"
    assert obs.severity == Severity.HIGH
    assert obs.location is not None
    assert obs.location.file_path == "Dockerfile"
    assert obs.location.line_start == 1
    assert obs.location.snippet and "FROM python:3.11" in obs.location.snippet


def test_trivy_adapter_missing_binary_skips_cleanly(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("vulnscan.scanners.trivy_adapter.which", lambda _name: None)
    adapter = TrivyAdapter()
    spec = ScanSpecification(
        run_id="r-skip",
        target_repository_url="local://demo",
        target_commit_sha="b" * 40,
        tools=[ToolConfig(tool=ToolName.TRIVY, enabled=True)],
    )
    res = adapter.run(spec, workdir=str(tmp_path))
    assert res.status == RunStatus.SKIPPED
    assert any("trivy" in err.lower() for err in res.errors)
