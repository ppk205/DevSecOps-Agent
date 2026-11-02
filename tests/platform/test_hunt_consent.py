"""B7: a cloud provider must not be called from scan-run without consent."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.platform.test_hunt_mode import FixtureAdapter
from vulnscan.contracts import ToolName
from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.core.config import ScanConfig
from vulnscan.core.scan_service import ScanService
from vulnscan.scanners.base import AdapterRegistry


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    path = tmp_path / "checkout"
    path.mkdir()
    (path / "Example.java").write_text("class Example {}\n", encoding="utf-8")
    for args in (
        ["init"],
        ["add", "."],
        ["-c", "user.name=Test", "-c", "user.email=t@example.invalid", "commit", "-m", "f"],
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
    return path


@pytest.fixture
def service(tmp_path: Path) -> ScanService:
    registry = AdapterRegistry()
    registry.register(FixtureAdapter())
    leaks = FixtureAdapter()
    leaks.tool = ToolName.GITLEAKS
    registry.register(leaks)
    return ScanService(str(tmp_path / "runs.db"), registry)


def _profile(base_url: str) -> ProviderProfile:
    return ProviderProfile(
        id="test-profile",
        label="Test",
        protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        base_url=base_url,
        api_key_env="TEST_KEY",
        models=["m"],
        default_model="m",
    )


def test_cloud_hunt_without_consent_skips_model_stages(
    service: ScanService, checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import vulnscan.providers.client as client_mod
    import vulnscan.providers.profile_store as store_mod

    monkeypatch.setattr(
        store_mod, "load_profile", lambda _id: _profile("https://api.test.invalid/v1")
    )

    def _no_client(*_args, **_kwargs):
        raise AssertionError("model called")

    monkeypatch.setattr(client_mod.ProviderClient, "__init__", _no_client)

    config = ScanConfig(
        output_dir=str(tmp_path / "reports"),
        mode="hunt",
        ai_review=True,
        ai_report=True,
        provider_profile="cloud-test",
    )
    result = service.run(str(checkout), config)
    stages = {e["stage"]: e for e in result["stages"]}
    for name in ("model_hunt", "targeted_deep_analysis", "final_report"):
        assert stages[name]["status"] == "skipped", name
        assert "--allow-cloud-model" in stages[name]["message"], name
    assert result["findings"] >= 1


def test_local_provider_without_consent_still_calls_model(
    service: ScanService, checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import vulnscan.ai.hunt as hunt_mod
    import vulnscan.providers.client as client_mod
    import vulnscan.providers.profile_store as store_mod

    monkeypatch.setattr(
        store_mod, "load_profile", lambda _id: _profile("http://127.0.0.1:11434/v1")
    )

    class _FakeClient:
        def __init__(self, *_args, **_kwargs):
            self.calls = 0

        def chat(self, *args, **kwargs):  # pragma: no cover - not reached
            raise AssertionError("unexpected provider call")

    monkeypatch.setattr(client_mod, "ProviderClient", _FakeClient)
    monkeypatch.setattr(
        hunt_mod,
        "hunt_vulns",
        lambda **kwargs: {
            "candidates": [],
            "rounds": 1,
            "usage": {},
            "status": "completed",
        },
    )
    config = ScanConfig(
        output_dir=str(tmp_path / "reports"),
        mode="hunt",
        provider_profile="local-test",
    )
    result = service.run(str(checkout), config)
    stages = {e["stage"]: e for e in result["stages"]}
    assert stages["model_hunt"]["status"] != "skipped"
    assert "--allow-cloud-model" not in json.dumps(result["stages"])
