"""Narrow redaction: key formats + loaded env values, nothing else."""

from __future__ import annotations

import pytest

from vulnscan.providers.credentials import CredentialError, load_api_key, redact


def test_load_api_key_returns_value(monkeypatch) -> None:
    monkeypatch.setenv("PROVIDER_API_KEY", "  sk-abc123  ")
    assert load_api_key("PROVIDER_API_KEY") == "sk-abc123"


@pytest.mark.parametrize("raw", ["", "   "])
def test_load_api_key_rejects_missing_or_blank(monkeypatch, raw: str) -> None:
    monkeypatch.setenv("PROVIDER_API_KEY", raw)
    with pytest.raises(CredentialError, match="PROVIDER_API_KEY"):
        load_api_key("PROVIDER_API_KEY")


def test_load_api_key_rejects_unset(monkeypatch) -> None:
    monkeypatch.delenv("PROVIDER_API_KEY", raising=False)
    with pytest.raises(CredentialError, match="PROVIDER_API_KEY"):
        load_api_key("PROVIDER_API_KEY")


@pytest.mark.parametrize(
    "snippet",
    [
        "if (token.isEmpty()) { return; }",
        "boolean ok = token.isEmpty();",
        "+ if (token.isEmpty()) {",
        "- String token = getToken();",
        '+ String secret = "not-a-real-key";',
        '{"token": "abc", "key": "value"}',
        '{"match": "token.isEmpty()", "secret": "none"}',
        "See docs for api_key and password handling.",
    ],
)
def test_benign_code_diff_and_json_pass_through(snippet: str) -> None:
    assert redact(snippet) == snippet


@pytest.mark.parametrize(
    "secret",
    [
        "sk-abcdefgh",
        "sk-projklmno",
        "ghp_abcdefgh",
        "github_pat_abcdefgh_1234",
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-abcdefgh",
        "xoxp-abcdefgh",
        "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
    ],
)
def test_known_key_formats_are_redacted(secret: str) -> None:
    text = f"leaked value {secret} in log line"
    redacted = redact(text)
    assert secret not in redacted
    assert "[REDACTED]" in redacted


@pytest.mark.parametrize("env_var", ["PROVIDER_API_KEY", "MODEL_TOKEN", "APP_SECRET"])
def test_loaded_env_values_are_redacted(monkeypatch, env_var: str) -> None:
    monkeypatch.setenv(env_var, "super-secret-value-123")
    text = "config dump: super-secret-value-123 done"
    assert redact(text) == "config dump: [REDACTED] done"


def test_env_values_are_read_at_call_time(monkeypatch) -> None:
    monkeypatch.setenv("PROVIDER_API_KEY", "call-time-secret-456")
    assert "call-time-secret-456" not in redact("holds call-time-secret-456 here")
    monkeypatch.delenv("PROVIDER_API_KEY")
    assert redact("holds call-time-secret-456 here") == "holds call-time-secret-456 here"


def test_short_and_nonsuffixed_env_values_pass_through(monkeypatch) -> None:
    monkeypatch.setenv("PROVIDER_API_KEY", "short")
    monkeypatch.setenv("PROVIDER_LABEL", "visible-label-value")
    assert redact("uses short and visible-label-value") == "uses short and visible-label-value"
