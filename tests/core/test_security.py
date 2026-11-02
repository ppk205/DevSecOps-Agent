"""Sanitize boundary: identifiers and JSON pass through; env secrets do not."""

from __future__ import annotations

import pytest

from vulnscan.core.security import sanitize


@pytest.mark.parametrize(
    "snippet",
    [
        "if (token.isEmpty()) { return; }",
        "+ if (token.isEmpty()) {",
        '{"token": "abc", "key": "value"}',
    ],
)
def test_identifiers_diff_and_json_pass_through(snippet: str) -> None:
    assert sanitize(snippet) == snippet


def test_loaded_env_secret_is_redacted(monkeypatch) -> None:
    monkeypatch.setenv("PROVIDER_API_KEY", "sanitize-boundary-secret-789")
    assert sanitize("holds sanitize-boundary-secret-789") == "holds [REDACTED]"
