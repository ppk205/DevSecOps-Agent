"""Consent gate for the baseline model stages (B7)."""

from __future__ import annotations

import pytest

from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.core.model_consent import is_local_base_url, model_use_allowed


def _profile(base_url: str) -> ProviderProfile:
    return ProviderProfile(
        id="test-profile",
        label="Test",
        protocol=ProviderProtocol.OPENAI_COMPATIBLE,
        base_url=base_url,
        api_key_env="TEST_API_KEY",
    )


@pytest.mark.parametrize(
    "url,local",
    [
        ("http://localhost:11434/v1", True),
        ("http://127.0.0.1:1234/v1", True),
        ("http://[::1]:8080/v1", True),
        ("https://api.deepseek.com", False),
        ("http://localhost.example.com", False),
    ],
)
def test_locality(url: str, local: bool) -> None:
    assert is_local_base_url(url) is local


def test_cloud_refused_without_flag() -> None:
    ok, reason = model_use_allowed(_profile("https://api.deepseek.com"), False)
    assert not ok
    assert "--allow-cloud-model" in reason


def test_cloud_allowed_with_flag() -> None:
    ok, reason = model_use_allowed(_profile("https://api.deepseek.com"), True)
    assert ok
    assert "--allow-cloud-model" in reason


def test_local_needs_no_flag() -> None:
    assert model_use_allowed(_profile("http://127.0.0.1:11434/v1"), False) == (
        True,
        "local provider",
    )
