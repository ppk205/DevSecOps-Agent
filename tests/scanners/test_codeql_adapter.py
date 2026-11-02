"""CodeQL adapter tests — missing-binary skip, SARIF parsing, coverage records.

All subprocess interaction is mocked: ``which`` is monkeypatched for the
absent/present binary cases and ``CodeQLAdapter._invoke`` stands in for the
``codeql database create`` / ``codeql database analyze`` calls. No test in
this module spawns a real process (the CodeQL CLI is not installed here).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vulnscan.contracts import (
    CoverageUnitStatus,
    CWECategory,
    ExtractionMode,
    RunStatus,
    ScanSpecification,
    Severity,
    ToolConfig,
    ToolName,
)
from vulnscan.scanners import codeql_adapter
from vulnscan.scanners.codeql_adapter import CodeQLAdapter, parse_codeql_sarif
from vulnscan.scanners.process import CommandResult

# --- CodeQL-style SARIF fixture ------------------------------------------- #

_FIXTURE_SARIF: dict[str, Any] = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "semanticVersion": "2.20.0",
                    "rules": [
                        {
                            "id": "java/sql-injection",
                            "name": "SqlInjection",
                            "properties": {
                                "tags": ["security", "external/cwe/cwe-089"],
                            },
                        },
                        {
                            "id": "java/reflected-xss",
                            "name": "ReflectedXss",
                            "properties": {
                                "tags": ["security", "external/cwe/cwe-079"],
                            },
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "java/sql-injection",
                    "ruleIndex": 0,
                    "level": "error",
                    "message": {"text": "This query depends on a user-provided value."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "src/main/java/com/example/Db.java"
                                },
                                "region": {
                                    "startLine": 42,
                                    "endLine": 44,
                                    "startColumn": 9,
                                    "endColumn": 40,
                                    "snippet": {"text": "stmt.executeQuery(query);"},
                                },
                            }
                        }
                    ],
                },
                {
                    "ruleId": "java/reflected-xss",
                    "ruleIndex": 1,
                    "level": "warning",
                    "message": {"text": "Cross-site scripting vulnerability."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "src/main/java/com/example/Web.java"
                                },
                                "region": {
                                    "startLine": 7,
                                    "endLine": 7,
                                    "startColumn": 5,
                                    "endColumn": 30,
                                },
                            }
                        }
                    ],
                },
            ],
        }
    ],
}


def _spec(tmp_path: Path, **kwargs: Any) -> ScanSpecification:
    metadata = {"configuration": {"output_dir": str(tmp_path / "artifacts")}}
    return ScanSpecification(
        run_id="run-codeql-1",
        target_repository_url="https://example.invalid/repo.git",
        target_commit_sha="abc123def456",
        repository_checkout_path=str(tmp_path),
        language="java",
        tools=[ToolConfig(tool=ToolName.CODEQL, enabled=True)],
        metadata=metadata,
        **kwargs,
    )


def _ok(extra: dict[str, Any] | None = None) -> CommandResult:
    return CommandResult(returncode=0, stdout="", stderr="", **(extra or {}))


# --- missing binary -------------------------------------------------------- #


def test_missing_binary_returns_skipped_with_actionable_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(codeql_adapter, "which", lambda name: None)
    adapter = CodeQLAdapter()

    assert adapter.capabilities().available is False
    result = adapter.run(_spec(tmp_path), workdir=str(tmp_path))

    assert result.status == RunStatus.SKIPPED
    assert result.observations == []
    assert any("codeql" in e.lower() and "path" in e.lower() for e in result.errors)


def test_disabled_tool_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(codeql_adapter, "which", lambda name: None)
    spec = _spec(tmp_path)
    spec.tools = [ToolConfig(tool=ToolName.CODEQL, enabled=False)]

    result = CodeQLAdapter().run(spec, workdir=str(tmp_path))

    assert result.status == RunStatus.SKIPPED


# --- SARIF parsing ---------------------------------------------------------- #


def test_parse_sarif_extracts_rule_cwe_and_snippet() -> None:
    observations, _ = parse_codeql_sarif(
        json.dumps(_FIXTURE_SARIF),
        run_id="run-codeql-1",
        tool_version="2.20.0",
        source_snapshot="abc123def456",
    )

    assert len(observations) == 2
    by_rule = {o.rule_id: o for o in observations}
    sql = by_rule["java/sql-injection"]
    assert sql.cwe_category == CWECategory.SQL_INJECTION
    assert sql.severity == Severity.HIGH
    assert sql.location.file_path == "src/main/java/com/example/Db.java"
    assert sql.location.line_start == 42
    assert sql.location.snippet == "stmt.executeQuery(query);"
    xss = by_rule["java/reflected-xss"]
    assert xss.cwe_category == CWECategory.XSS
    assert xss.location.snippet is None


def test_parse_sarif_maps_coverage_per_file() -> None:
    _, coverage = parse_codeql_sarif(
        json.dumps(_FIXTURE_SARIF),
        run_id="run-codeql-1",
        tool_version="2.20.0",
        source_snapshot="abc123def456",
    )

    assert {c.unit_path for c in coverage} == {
        "src/main/java/com/example/Db.java",
        "src/main/java/com/example/Web.java",
    }
    assert all(c.status == CoverageUnitStatus.ANALYZED for c in coverage)
    assert all(c.extraction_mode == ExtractionMode.DATAFLOW for c in coverage)
    assert all(c.tool == ToolName.CODEQL for c in coverage)
    db_record = next(c for c in coverage if c.unit_path.endswith("Db.java"))
    assert CWECategory.SQL_INJECTION in db_record.cwe_capabilities


def test_parse_sarif_rejects_non_object() -> None:
    with pytest.raises(TypeError):
        parse_codeql_sarif(
            "[1, 2]",
            run_id="run-codeql-1",
            tool_version="2.20.0",
            source_snapshot="abc123def456",
        )


# --- run() with mocked subprocess ------------------------------------------- #


def _fake_invoke_factory(
    monkeypatch: pytest.MonkeyPatch,
    adapter: CodeQLAdapter,
    recorded: list[list[str]],
) -> None:
    """Fake ``codeql database create`` + ``analyze`` around the fixture SARIF."""

    def fake(argv: Any, *, cwd: str, **kwargs: Any) -> CommandResult:
        recorded.append([str(a) for a in argv])
        parts = [str(a) for a in argv]
        if "create" in parts:
            db_dir = Path(parts[parts.index("create") + 1])
            db_dir.mkdir(parents=True, exist_ok=True)
            (db_dir / "codeql-database.yml").write_text("placeholder", encoding="utf-8")
            return _ok()
        if "analyze" in parts:
            out = next((p.split("=", 1)[1] for p in parts if p.startswith("--output=")), None)
            assert out is not None
            Path(out).write_text(json.dumps(_FIXTURE_SARIF), encoding="utf-8")
            return _ok({"duration_ms": 5})
        raise AssertionError(f"unexpected codeql invocation: {parts}")

    monkeypatch.setattr(adapter, "_invoke", fake)


def test_run_creates_database_and_analyzes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(codeql_adapter, "which", lambda name: "/usr/bin/codeql")
    adapter = CodeQLAdapter()
    recorded: list[list[str]] = []
    _fake_invoke_factory(monkeypatch, adapter, recorded)

    result = adapter.run(_spec(tmp_path), workdir=str(tmp_path))

    assert result.status == RunStatus.COMPLETED
    assert [o.rule_id for o in result.observations] == [
        "java/sql-injection",
        "java/reflected-xss",
    ]
    assert len(result.coverage_records) == 2
    assert any("create" in cmd for cmd in recorded)
    assert any("analyze" in cmd for cmd in recorded)
    assert any("security-extended" in arg for cmd in recorded for arg in cmd)
    assert any("--source-root=" in arg for cmd in recorded for arg in cmd)


def test_run_reuses_cached_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(codeql_adapter, "which", lambda name: "/usr/bin/codeql")
    adapter = CodeQLAdapter()
    cached = tmp_path / "artifacts" / "codeql-db" / "abc123def456" / "java"
    cached.mkdir(parents=True, exist_ok=True)
    (cached / "codeql-database.yml").write_text("cached", encoding="utf-8")
    recorded: list[list[str]] = []
    _fake_invoke_factory(monkeypatch, adapter, recorded)

    result = adapter.run(_spec(tmp_path), workdir=str(tmp_path))

    assert result.status == RunStatus.COMPLETED
    assert not any("create" in cmd for cmd in recorded)
    assert any("analyze" in cmd for cmd in recorded)
    assert result.metadata["codeql_db_reused"] == {"java": True}


def test_run_analyze_failure_is_failed_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(codeql_adapter, "which", lambda name: "/usr/bin/codeql")
    adapter = CodeQLAdapter()

    def fake(argv: Any, *, cwd: str, **kwargs: Any) -> CommandResult:
        parts = [str(a) for a in argv]
        if "create" in parts:
            db_dir = Path(parts[parts.index("create") + 1])
            db_dir.mkdir(parents=True, exist_ok=True)
            (db_dir / "codeql-database.yml").write_text("placeholder", encoding="utf-8")
            return _ok()
        return CommandResult(returncode=2, stdout="", stderr="boom")

    monkeypatch.setattr(adapter, "_invoke", fake)

    result = adapter.run(_spec(tmp_path), workdir=str(tmp_path))

    assert result.status == RunStatus.FAILED
    assert result.observations == []
