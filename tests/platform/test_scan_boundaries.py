"""DR-09 / QR-22: migrations, credential exclusion and malformed scanner output."""

import json
import sqlite3
import sys
from datetime import UTC

import pytest

from vulnscan.contracts import ScanSpecification, ToolName
from vulnscan.core.config import resolve_config
from vulnscan.core.security import sanitize
from vulnscan.scanners.base import AdapterCapability
from vulnscan.scanners.gitleaks_adapter import GitleaksAdapter, parse_gitleaks_json
from vulnscan.scanners.process import CommandResult, run_command
from vulnscan.scanners.semgrep_adapter import SemgrepAdapter, parse_json
from vulnscan.storage.database import get_session, init_db
from vulnscan.storage.models import RunORM, TargetORM


def test_dr09_additive_migration_preserves_integer_history(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
        CREATE TABLE targets (id INTEGER PRIMARY KEY, repository_url TEXT, commit_sha TEXT, created_at DATETIME);
        CREATE TABLE runs (id INTEGER PRIMARY KEY, target_id INTEGER, attempt INTEGER, status TEXT, scan_spec_json TEXT, created_at DATETIME, updated_at DATETIME);
        INSERT INTO targets VALUES (7, 'local', 'abcd', '2025-01-01 12:00:00');
        INSERT INTO runs VALUES (9, 7, 1, 'completed', '{}', '2025-01-01 12:00:00', '2025-01-01 12:00:00');
        """)
    init_db(path)
    init_db(path)
    with get_session(path) as session:
        row = session.get(RunORM, 9)
        assert row.target_id == 7 and row.status == "completed"
        assert row.created_at.tzinfo == UTC
    with sqlite3.connect(path) as conn:
        assert (
            conn.execute("SELECT created_at FROM runs WHERE id=9").fetchone()[0].endswith("+00:00")
        )
        assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 2


def test_dr09_database_paths_are_independent(tmp_path):
    first, second = tmp_path / "one.db", tmp_path / "two.db"
    init_db(first)
    init_db(second)
    with get_session(first) as session:
        session.add(TargetORM(repository_url="one", commit_sha="one"))
    with get_session(second) as session:
        assert session.query(TargetORM).count() == 0


def test_qr22_secret_output_and_config_diagnostics_are_redacted(tmp_path, monkeypatch):
    secret = "synthetic-test-secret-1234567890"
    monkeypatch.setenv("PROVIDER_API_KEY", secret)
    observations, _ = parse_gitleaks_json(
        [{"RuleID": "generic-api-key", "File": "A.java", "StartLine": 1, "Match": secret}],
        run_id="r",
        tool_version="8.24.2",
        source_snapshot="abcd",
    )
    assert secret not in observations[0].model_dump_json()
    assert secret not in json.dumps(sanitize({"message": secret, "Secret": secret}))
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"schema_version": 1, "api_key": secret}))
    with pytest.raises(ValueError) as exc:
        resolve_config(config=str(path))
    assert secret not in str(exc.value)


def test_fr72_semgrep_current_coverage_format():
    _, coverage = parse_json(
        '{"results":[],"paths":{"scanned":["A.java"]}}',
        run_id="r",
        tool_version="1.178.0",
        source_snapshot="abcd",
    )
    assert coverage[0].unit_path == "A.java"
    assert coverage[0].analyzed_at.tzinfo == UTC


@pytest.mark.parametrize("payload", ["not-json", '{"unexpected": true}'])
def test_fr72_malformed_semgrep_fails(payload, monkeypatch, tmp_path):
    adapter = SemgrepAdapter()
    monkeypatch.setattr(
        adapter, "capabilities", lambda: AdapterCapability(ToolName.SEMGREP, available=True)
    )
    monkeypatch.setattr(adapter, "_invoke", lambda *a, **k: CommandResult(0, stdout=payload))
    spec = ScanSpecification(run_id="r", target_repository_url="local", target_commit_sha="abcd")
    assert not adapter.run(spec, workdir=str(tmp_path)).is_complete


def test_fr72_gitleaks_missing_report_never_passes(monkeypatch, tmp_path):
    adapter = GitleaksAdapter()
    monkeypatch.setattr(
        adapter, "capabilities", lambda: AdapterCapability(ToolName.GITLEAKS, available=True)
    )
    monkeypatch.setattr(adapter, "_invoke", lambda *a, **k: CommandResult(0))
    spec = ScanSpecification(run_id="r", target_repository_url="local", target_commit_sha="abcd")
    assert not adapter.run(spec, workdir=str(tmp_path)).is_complete


def test_qr21_timeout_is_an_execution_failure():
    result = run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2)
    assert result.timed_out and not result.succeeded


def test_native_cvss_v4_severity_is_preserved():
    from vulnscan.contracts import Severity
    from vulnscan.scanners.dependency_check_adapter import parse_dependency_check_json

    observations, _ = parse_dependency_check_json(
        {
            "dependencies": [
                {
                    "fileName": "fixture.jar",
                    "vulnerabilities": [{"name": "fixture-CVE", "cvssv4": {"baseScore": 9.3}}],
                }
            ]
        },
        run_id="fixture",
        tool_version="13.0.0",
        source_snapshot="abcd",
    )
    assert observations[0].severity == Severity.CRITICAL
