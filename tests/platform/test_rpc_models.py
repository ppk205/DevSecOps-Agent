"""FR-48/71, IR-11: model choices expose aliases and runtime key status only."""

import json
import threading

from tests.platform.test_scan_service import checkout, service
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.core import rpc
from vulnscan.core.config import ScanConfig
from vulnscan.infra import envfile
from vulnscan.providers import profile_store

__all__ = ["checkout", "service"]


def setup_profile(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").touch()
    monkeypatch.chdir(tmp_path)
    loads = []

    class FakeEnv:
        def load_into_environ(self):
            loads.append(True)
            return []

    monkeypatch.setattr(envfile, "EnvFile", FakeEnv)
    monkeypatch.setattr(rpc, "EnvFile", FakeEnv)
    profile = ProviderProfile(
        id="test-profile",
        label="Test profile",
        protocol="openai_compatible",
        base_url="https://offline.invalid/v1",
        api_key_env="TEST_NATIVE_API_KEY",
        models=["test-model"],
        default_model="test-model",
    )
    profile_store.save_profile(profile, base=tmp_path / ".providers")
    monkeypatch.setenv(profile.api_key_env, "never-emit-this-test-placeholder")
    monkeypatch.setattr(profile_store, "default_profile", lambda: profile)
    return profile, loads


def test_ir11_model_list_never_returns_credentials_or_environment_names(
    service, tmp_path, monkeypatch
):
    profile, _ = setup_profile(tmp_path, monkeypatch)
    result = rpc.ServiceRPC(service).dispatch("model_profiles", {}, "models", threading.Event())
    item = result["profiles"][0]
    assert item["id"] == profile.id and item["key_set"] is True
    assert item["default_model"] == "test-model"
    assert profile.api_key_env not in json.dumps(result)
    assert "never-emit-this-test-placeholder" not in json.dumps(result)


def test_fr48_review_resolves_the_provider_and_model_that_will_run(
    service, checkout, tmp_path, monkeypatch
):
    profile, loads = setup_profile(tmp_path, monkeypatch)
    cfg = ScanConfig(mode="hunt", laya=False)
    result = rpc.ServiceRPC(service).dispatch(
        "review",
        {"checkout": str(checkout), "configuration": cfg.model_dump()},
        "review",
        threading.Event(),
    )
    assert loads
    assert result["configuration"]["provider_profile"] == profile.id
    assert result["configuration"]["provider_model"] == "test-model"
    assert result["ai_support"]["status"] == "ready"


def test_fr48_deterministic_review_does_not_load_credentials(
    service, checkout, tmp_path, monkeypatch
):
    _, loads = setup_profile(tmp_path, monkeypatch)
    result = rpc.ServiceRPC(service).dispatch(
        "review",
        {
            "checkout": str(checkout),
            "configuration": ScanConfig(mode="deterministic", laya=False).model_dump(),
        },
        "review",
        threading.Event(),
    )
    assert loads == []
    assert result["ai_support"]["status"] == "disabled"


def test_ir11_profiles_resolve_from_project_root_when_launched_inside_bin(tmp_path, monkeypatch):
    profile, _ = setup_profile(tmp_path, monkeypatch)
    (tmp_path / "bin").mkdir()
    monkeypatch.chdir(tmp_path / "bin")
    assert profile_store.load_profile(profile.id).id == profile.id
