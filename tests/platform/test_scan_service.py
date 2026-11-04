"""FR-70..73 / DR-09..10 / IR-15: shared execution and honest policy."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnscan.cli.main import app
from vulnscan.contracts import (
    CoverageRecord,
    CoverageUnitStatus,
    CWECategory,
    Finding,
    FindingStatus,
    Observation,
    RunStatus,
    ScannerResult,
    Severity,
    SourceCoordinate,
    ToolName,
)
from vulnscan.core.config import ScanConfig, resolve_config
from vulnscan.core.policy import gate
from vulnscan.core.scan_service import ScanService, checkout_manifest
from vulnscan.scanners.base import AdapterCapability, AdapterRegistry, ScannerAdapter
from vulnscan.scanners.process import ScanCancelled, _cancel_check, run_command
from vulnscan.storage.database import get_session
from vulnscan.storage.models import RunORM
from vulnscan.version import APP_VERSION


@pytest.fixture
def checkout(tmp_path):
    path = tmp_path / "checkout"
    path.mkdir()
    (path / "Example.java").write_text("class Example {}")
    for args in [
        ["init"],
        ["add", "."],
        [
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "fixture",
        ],
    ]:
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
    return path


class FixtureAdapter(ScannerAdapter):
    tool = ToolName.SEMGREP
    binary_name = "fixture"

    def capabilities(self):
        return AdapterCapability(self.tool, available=True)

    def run(self, spec, *, workdir):
        now = datetime.now(UTC)
        return ScannerResult(
            run_id=spec.run_id,
            tool=self.tool,
            tool_version="test",
            adapter_version="test",
            status=RunStatus.COMPLETED,
            started_at=now,
            observations=[
                Observation(
                    observation_id=self.tool.value + "-test",
                    run_id=spec.run_id,
                    tool=self.tool,
                    tool_version="test",
                    rule_id="test-low",
                    severity=Severity.LOW,
                    cwe_category=CWECategory.SQL_INJECTION,
                    message="Fixture evidence",
                    detected_at=now,
                    location=SourceCoordinate(file_path="Example.java", line_start=1),
                )
            ],
            coverage_records=[
                CoverageRecord(
                    run_id=spec.run_id,
                    tool=self.tool,
                    tool_version="test",
                    source_snapshot=spec.target_commit_sha,
                    unit_path="Example.java",
                    eligible=True,
                    status=CoverageUnitStatus.ANALYZED,
                    analyzed_at=now,
                )
            ],
        )


@pytest.fixture
def service(tmp_path):
    registry = AdapterRegistry()
    registry.register(FixtureAdapter())
    leaks = FixtureAdapter()
    leaks.tool = ToolName.GITLEAKS
    registry.register(leaks)
    return ScanService(str(tmp_path / "runs.db"), registry)


def settings(tmp_path, **kwargs):
    return ScanConfig(output_dir=str(tmp_path / "reports"), **kwargs)


def test_fr70_persist_export_restart_and_retry(service, checkout, tmp_path):
    result = service.run(str(checkout), settings(tmp_path))
    assert result["exit_code"] == 0
    assert (
        result["commit"]
        == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    )
    restarted = ScanService(service.db_path, service.registry)
    detail = restarted.detail(result["id"])
    assert detail["spec"]["run_id"] == result["run_id"]
    assert detail["events"][0]["timestamp"].endswith("+00:00")
    report = Path(result["reports"]["json"])
    old_bytes = report.read_bytes()
    second = restarted.retry(result["id"])
    assert second["run_id"] != result["run_id"]
    assert restarted.history()[0]["attempt"] == 2
    assert report.read_bytes() == old_bytes
    assert restarted.detail(result["id"])["status"] == "completed"


def test_fr72_missing_scanner_is_failure_with_reports(service, checkout, tmp_path):
    service.registry.adapters.pop("gitleaks")
    result = service.run(str(checkout), settings(tmp_path))
    assert result["exit_code"] == 2
    assert Path(result["summary_path"]).exists()
    assert Path(result["reports"]["sarif"]).exists()
    report = json.loads(Path(result["reports"]["json"]).read_text())
    assert report["scan_metadata"]["status"] == "failed"
    sarif = json.loads(Path(result["reports"]["sarif"]).read_text())
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert "required scanner" in Path(result["reports"]["html"]).read_text()


def test_fr72_missing_coverage_cannot_pass(service, checkout, tmp_path, monkeypatch):
    adapter = service.registry.get("semgrep")
    original = adapter.run

    def missing(*args, **kwargs):
        result = original(*args, **kwargs)
        result.coverage_records = []
        return result

    monkeypatch.setattr(adapter, "run", missing)
    result = service.run(str(checkout), settings(tmp_path))
    assert result["exit_code"] == 2
    assert any("missing coverage" in e for e in result["errors"])


def test_fr73_dirty_checkout_requires_explicit_manifest(checkout, tmp_path):
    (checkout / "Example.java").write_text("class Changed {}")
    with pytest.raises(ValueError, match="dirty checkout"):
        checkout_manifest(str(checkout), settings(tmp_path))
    manifest = checkout_manifest(str(checkout), settings(tmp_path, allow_dirty=True))
    assert manifest["dirty"] and len(manifest["files"]["Example.java"]) == 64
    with pytest.raises(ValueError, match="dirty checkout"):
        checkout_manifest(str(checkout), settings(tmp_path, allow_dirty=True, ci=True))


def test_dr09_live_owner_not_recovered_and_concurrent_process_rejected(service, checkout, tmp_path):
    # A different interpreter owns the OS lock, proving this is not merely a thread guard.
    code = "from filelock import FileLock; import sys; lock=FileLock(sys.argv[1]); lock.acquire(); print('ready',flush=True); sys.stdin.readline()"
    proc = subprocess.Popen(
        [sys.executable, "-c", code, service.db_path + ".lock"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout.readline().strip() == "ready"
        service.recover()
        with pytest.raises(ValueError, match="another scan"):
            service.run(str(checkout), settings(tmp_path))
    finally:
        proc.communicate("done\n", timeout=10)


def test_dr09_recovery_preserves_results(service, checkout, tmp_path):
    result = service.run(str(checkout), settings(tmp_path))
    with get_session(service.db_path) as session:
        row = session.get(RunORM, result["id"])
        row.status = "running"
    service.recover()
    detail = service.detail(result["id"])
    assert detail["status"] == "interrupted"
    assert detail["result"]["exit_code"] == 130
    assert detail["result"]["reports"] == result["reports"]


def test_qr21_cancel_retains_completed_scanner_evidence(service, checkout, tmp_path):
    def cancel(event):
        if event.stage == "semgrep" and event.status == "completed":
            service.cancel(service.history()[0]["id"])

    result = service.run(str(checkout), settings(tmp_path), on_event=cancel)
    assert result["exit_code"] == 130
    assert len(result["scanner_results"]) == 1
    assert Path(result["summary_path"]).exists()


def test_qr22_subprocess_credentials_excluded_and_cancelled(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "private-token-never-inherit")
    result = run_command(
        [sys.executable, "-c", "import os; print(os.getenv('GITHUB_TOKEN','absent'))"]
    )
    assert result.stdout.strip() == "absent"
    token = _cancel_check.set(lambda: True)
    try:
        with pytest.raises(ScanCancelled):
            run_command([sys.executable, "-c", "import time; time.sleep(60)"], timeout=5)
    finally:
        _cancel_check.reset(token)


def test_ir15_cli_uses_same_gate(service, checkout, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("vulnscan.core.scan_service.ScanService", lambda _: service)
    result = CliRunner().invoke(
        app, ["scan-run", "--checkout", str(checkout), "--out", str(tmp_path / "reports"), "--json"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["gate"] == "passed"
    assert CliRunner().invoke(app, ["--version"]).stdout.strip() == APP_VERSION
    assert "Usage:" in CliRunner().invoke(app, []).stdout


def test_dr10_configuration_precedence_and_unknown_fields(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"schema_version": 1, "profile": "full", "fail_on": "medium"}))
    config = resolve_config("fast", str(path), fail_on="critical")
    assert config.profile == "full" and config.fail_on == "critical"
    path.write_text('{"schema_version":1,"api_key":"forbidden"}')
    with pytest.raises(ValueError):
        resolve_config(config=str(path))


@pytest.mark.parametrize(
    "severity,status,independent,expected,unknown",
    [
        ("high", "unprocessed", False, 1, 0),
        ("critical", "unresolved", False, 1, 0),
        ("high", "rejected", False, 1, 0),
        ("high", "rejected", True, 0, 0),
        ("undetermined", "unresolved", False, 0, 1),
        ("low", "confirmed", False, 0, 0),
    ],
)
def test_fr72_policy_outcomes(severity, status, independent, expected, unknown):
    now = datetime.now(UTC)
    finding = Finding(
        finding_id="f",
        run_id="r",
        fingerprint="f",
        title="test",
        cwe_category=CWECategory.SQL_INJECTION,
        severity=Severity(severity),
        status=FindingStatus(status),
        created_at=now,
        updated_at=now,
        metadata={
            "validation_decision": {"decided_by": "independent-validator", "new_status": "rejected"}
        }
        if independent
        else {},
    )
    result = gate([finding], [], [], "high", [])
    assert result["exit_code"] == expected
    assert len(result["unknown_severity"]) == unknown
    assert gate([finding], [], ["semgrep"], "high", [])["exit_code"] == 2


def test_qr22_run_id_cannot_escape_artifact_root(service, checkout, tmp_path):
    with pytest.raises(ValueError, match="run ID"):
        service.run(str(checkout), settings(tmp_path), public_id="../escape")


def test_fr73_action_transport_uses_shared_policy(service, checkout, tmp_path, monkeypatch):
    import runpy

    root = Path(__file__).parents[2]
    values = {
        "ACTION_ROOT": str(root),
        "SCAN_OUTPUT": str(tmp_path / "reports"),
        "RUNNER_TEMP": str(tmp_path),
        "SCAN_PROFILE": "fast",
        "SCAN_CONFIG": "",
        "SCAN_THRESHOLD": "high",
        "SCAN_CHECKOUT": str(checkout),
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "job-summary"),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("vulnscan.core.scan_service.ScanService", lambda _: service)
    runpy.run_path(str(root / "ci/action_scan.py"))
    result = service.detail(service.history()[0]["id"])["result"]
    assert result["exit_code"] == 0 and result["gate"] == "passed"
    assert "**passed**" in (tmp_path / "job-summary").read_text()
    assert result["run_id"] in (tmp_path / "outputs").read_text()


def test_ir14_web_command_remains_local(monkeypatch):
    result = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0"])
    assert result.exit_code == 2


def test_local_runtime_files_do_not_dirty_the_source_snapshot(service, checkout):
    local = ScanService(str(checkout / "runs.db"), service.registry)
    config = ScanConfig(output_dir=str(checkout / "artifacts"))
    first = local.run(str(checkout), config)
    assert first["exit_code"] == 0
    assert first["manifest"]["files"].keys() == {"Example.java"}
    assert first["manifest"]["runtime_exclusions"]
    assert local.retry(first["id"])["exit_code"] == 0
    strict = local.run(str(checkout), config.model_copy(update={"ci": True}))
    assert strict["exit_code"] == 2


def test_ir15_database_failure_is_execution_exit_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app, ["scan-run", "--db-path", str(tmp_path), "--out", str(tmp_path / "reports"), "--json"]
    )
    assert result.exit_code == 2
    summary = json.loads(result.stdout)
    assert summary["exit_code"] == 2 and summary["status"] == "failed"
