"""Native-hunt adapter: livesqli must yield the known SQLi + XSS."""

from __future__ import annotations

from vulnscan.contracts import RunStatus, ToolName
from vulnscan.core.config import PROFILES
from vulnscan.scanners.base import AdapterRegistry
from vulnscan.scanners.native_hunt_adapter import NativeHuntAdapter


def test_registered_in_default_registry() -> None:
    registry = AdapterRegistry.default()
    assert ToolName.NATIVE_HUNT in registry


def test_profiles_include_native_hunt() -> None:
    assert ToolName.NATIVE_HUNT in PROFILES["fast"]
    assert ToolName.NATIVE_HUNT in PROFILES["full"]


def test_livesqli_finds_known_vulns(tmp_path) -> None:
    import shutil

    from vulnscan.contracts import ScanSpecification, ToolConfig

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
