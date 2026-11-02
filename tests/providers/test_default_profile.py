"""default_profile(): first keyed provider profile, else None."""

from __future__ import annotations

from pathlib import Path

from vulnscan.contracts.provider import ProviderProfile
from vulnscan.providers.profile_store import default_profile, save_profile


def _write(base: Path, pid: str, env: str) -> None:
    save_profile(
        ProviderProfile(
            id=pid,
            label=pid,
            protocol="openai_compatible",
            base_url="https://example.test/v1",
            api_key_env=env,
            models=[pid],
        ),
        base=base,
    )


def test_returns_none_without_keys(tmp_path, monkeypatch) -> None:
    _write(tmp_path, "b-profile", "TEST_MISSING_KEY_A")
    _write(tmp_path, "a-profile", "TEST_MISSING_KEY_B")
    monkeypatch.delenv("TEST_MISSING_KEY_A", raising=False)
    monkeypatch.delenv("TEST_MISSING_KEY_B", raising=False)
    assert default_profile(base=tmp_path) is None


def test_returns_keyed_profile_preferring_opencode(tmp_path, monkeypatch) -> None:
    _write(tmp_path, "zz-other", "TEST_KEY_OTHER")
    _write(tmp_path, "opencode-free", "TEST_KEY_OPENCODE")
    monkeypatch.setenv("TEST_KEY_OTHER", "x")
    monkeypatch.setenv("TEST_KEY_OPENCODE", "y")
    picked = default_profile(base=tmp_path)
    assert picked is not None and picked.id == "opencode-free"


def test_skips_malformed_files(tmp_path, monkeypatch) -> None:
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    _write(tmp_path, "only", "TEST_KEY_ONLY")
    monkeypatch.setenv("TEST_KEY_ONLY", "z")
    picked = default_profile(base=tmp_path)
    assert picked is not None and picked.id == "only"
