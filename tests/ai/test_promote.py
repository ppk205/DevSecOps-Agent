"""Promotion of verified model-only candidates to model-origin Findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnscan.ai.promote import promote_model_only
from vulnscan.contracts.enums import (
    CWECategory,
    FindingProvenance,
    FindingStatus,
    Severity,
)
from vulnscan.contracts.finding import Finding


def _snapshot(tmp_path: Path) -> str:
    src = tmp_path / "src"
    src.mkdir()
    (src / "LoginServlet.java").write_text(
        "".join(f'String line{i} = "x";\n' for i in range(1, 31)),
        encoding="utf-8",
    )
    (src / "Empty.java").write_text("", encoding="utf-8")
    return str(tmp_path)


def _candidate(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": "SQL injection",
        "file": "src/LoginServlet.java",
        "line": 6,
        "cwe": "CWE-89",
        "severity": "high",
        "rationale": "tainted flow into executeQuery",
        "evidence": "executeQuery(",
    }
    base.update(overrides)
    return base


class TestPromoteModelOnly:
    def test_escape_path_dropped(self, tmp_path: Path) -> None:
        root = _snapshot(tmp_path)
        out = promote_model_only(
            [_candidate(file="../outside.java"), _candidate(file="/etc/passwd")],
            snapshot_root=root,
            run_id="r1",
        )
        assert out == []

    def test_empty_excerpt_dropped(self, tmp_path: Path) -> None:
        root = _snapshot(tmp_path)
        out = promote_model_only(
            [
                _candidate(file="src/Empty.java", line=1),
                _candidate(file="src/Missing.java", line=1),
                _candidate(line=0),
                _candidate(line="nan"),
            ],
            snapshot_root=root,
            run_id="r1",
        )
        assert out == []

    def test_good_candidate_promotes_with_provenance_model(self, tmp_path: Path) -> None:
        root = _snapshot(tmp_path)
        out = promote_model_only([_candidate()], snapshot_root=root, run_id="r1")
        assert len(out) == 1
        finding = out[0]
        assert finding.provenance == FindingProvenance.MODEL
        assert finding.model_dump(mode="json")["provenance"] == "model"
        assert "origin" not in finding.metadata
        assert finding.metadata["title"] == "SQL injection"
        assert finding.metadata["rationale"] == "tainted flow into executeQuery"
        assert finding.metadata["evidence"] == "executeQuery("
        assert finding.status == FindingStatus.UNPROCESSED
        assert finding.severity == Severity.HIGH
        assert finding.cwe_category == CWECategory.SQL_INJECTION
        assert len(finding.observations) == 1
        obs = finding.observations[0]
        assert obs.rule_id == "model-hunt"
        assert obs.location.file_path == "src/LoginServlet.java"
        assert obs.location.line_start == 6

    def test_bad_severity_defaults(self, tmp_path: Path) -> None:
        root = _snapshot(tmp_path)
        out = promote_model_only(
            [_candidate(severity="bogus"), _candidate(severity=None)],
            snapshot_root=root,
            run_id="r1",
        )
        assert [f.severity for f in out] == [Severity.MEDIUM, Severity.MEDIUM]

    def test_never_raises_on_garbage(self, tmp_path: Path) -> None:
        root = _snapshot(tmp_path)
        out = promote_model_only(
            [None, 42, {}, {"file": "", "line": -3}],  # type: ignore[list-item]
            snapshot_root=root,
            run_id="r1",
        )
        assert out == []

    def test_missing_provenance_validates_as_none(self, tmp_path: Path) -> None:
        # Pre-contract rows carry no provenance; absent means scanner.
        root = _snapshot(tmp_path)
        (finding,) = promote_model_only([_candidate()], snapshot_root=root, run_id="r1")
        dumped = finding.model_dump(mode="json")
        dumped.pop("provenance")
        assert Finding.model_validate(dumped).provenance is None
