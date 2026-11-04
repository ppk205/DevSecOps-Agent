"""Native-hunt adapter: livesqli must yield the known SQLi + XSS."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from vulnscan.contracts import CoverageUnitStatus, RunStatus, ScanSpecification, ToolName
from vulnscan.core.config import PROFILES, ScanConfig
from vulnscan.core.scan_service import ScanService
from vulnscan.scanners.base import AdapterRegistry
from vulnscan.scanners.native_hunt_adapter import NativeHuntAdapter

FIXTURES = Path(__file__).resolve().parents[1] / "native_hunt" / "fixtures"


def test_registered_in_default_registry() -> None:
    registry = AdapterRegistry.default()
    assert ToolName.NATIVE_HUNT in registry


def test_profiles_include_native_hunt() -> None:
    assert ToolName.NATIVE_HUNT in PROFILES["fast"]
    assert ToolName.NATIVE_HUNT in PROFILES["full"]


def test_livesqli_finds_known_vulns(tmp_path) -> None:
    from vulnscan.contracts import ToolConfig

    checkout = tmp_path / "livesqli"
    shutil.copytree("D:/livesqli", checkout)
    spec = ScanSpecification(
        run_id="run-native-test",
        target_repository_url="https://example.invalid/livesqli.git",
        target_commit_sha="abc123",
        repository_checkout_path=str(checkout),
        tools=[ToolConfig(tool=ToolName.NATIVE_HUNT)],
    )
    result = NativeHuntAdapter().run(spec, workdir=str(checkout))
    assert result.status == RunStatus.COMPLETED
    assert result.errors == []
    rules = {o.rule_id for o in result.observations}
    assert "java-sql-concatenation" in rules
    assert "java-xss-response-writer" in rules
    assert result.analyzed_units >= 1


def _fixture_result():
    spec = ScanSpecification(
        run_id="run-native-families",
        target_repository_url="https://example.invalid/families.git",
        target_commit_sha="abc123",
    )
    return NativeHuntAdapter().run(spec, workdir=str(FIXTURES))


@pytest.mark.parametrize(
    "path,language,prefix",
    [
        ("go/Vuln.go", "go", "go-"),
        ("ruby/Vuln.rb", "ruby", "rb-"),
        ("csharp/Vuln.cs", "csharp", "cs-"),
    ],
)
def test_adapter_runs_go_ruby_csharp_packs(path: str, language: str, prefix: str) -> None:
    result = _fixture_result()
    found = [o for o in result.observations if o.location.file_path == path]
    assert found
    assert all(o.rule_id.startswith(prefix) for o in found)
    assert {o.location.language.value for o in found} == {language}
    coverage = {c.unit_path: c for c in result.coverage_records}[path]
    assert coverage.status == CoverageUnitStatus.ANALYZED
    assert coverage.unit_language.value == language


@pytest.mark.parametrize("path", ["go/Safe.go", "ruby/Safe.rb", "csharp/Safe.cs"])
def test_adapter_stays_silent_on_safe_controls(path: str) -> None:
    result = _fixture_result()
    assert [o.rule_id for o in result.observations if o.location.file_path == path] == []
    assert path in {c.unit_path for c in result.coverage_records}


@pytest.mark.parametrize(
    "family,inventoried",
    [("go", "go/Vuln.go"), ("ruby", "ruby/View.erb"), ("csharp", "csharp/View.cshtml")],
)
def test_scan_run_reports_findings_for_single_language_target(
    tmp_path: Path, family: str, inventoried: str
) -> None:
    """A vulnerable target in one of these languages must not pass as clean."""
    checkout = tmp_path / "checkout"
    shutil.copytree(FIXTURES / family, checkout / family)
    registry = AdapterRegistry()
    registry.register(NativeHuntAdapter())
    service = ScanService(str(tmp_path / "runs.db"), registry)
    result = service.run(
        str(checkout),
        ScanConfig(
            output_dir=str(tmp_path / "reports"),
            tools=["native-hunt"],
            mode="deterministic",
            laya=False,
            allow_dirty=True,
        ),
    )
    assert result["errors"] == []
    assert result["findings"]
    assert result["gate"] == "failed"
    assert result["exit_code"] == 1
    assert inventoried in result["manifest"]["inventory"]
