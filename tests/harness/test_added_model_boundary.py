"""Added models must use URL locality and redact model-owned credentials."""

import json

import httpx
import pytest

from vulnscan.harness.messages import ProviderError
from vulnscan.harness.providers import (
    BUILTIN_PROFILES,
    AnthropicTransport,
    ChatCompletionsTransport,
    is_local,
)
from vulnscan.providers.credentials import redact_json


@pytest.mark.parametrize(
    "url,metadata,expected",
    [
        ("https://remote.example/v1", {"local": True}, False),
        ("http://127.0.0.1:11434/v1", {}, True),
        ("http://localhost.example/v1", {"local": True}, False),
        ("http://[::1]:1234/v1", {}, True),
    ],
)
def test_locality_comes_from_url(url: str, metadata: dict[str, bool], expected: bool) -> None:
    profile = BUILTIN_PROFILES["ollama"].model_copy(update={"base_url": url, "metadata": metadata})
    assert is_local(profile) is expected


@pytest.mark.parametrize("sentinel", ["synthetic-model-owned-credential", "xyz"])
def test_model_owned_key_is_redacted(monkeypatch: pytest.MonkeyPatch, sentinel: str) -> None:
    monkeypatch.setenv("DEVSEC_KEY_CUSTOM", sentinel)
    assert json.loads(redact_json({"nested": [sentinel]})) == {"nested": ["[REDACTED]"]}


@pytest.mark.parametrize(
    "template,transport_class",
    [("deepseek", ChatCompletionsTransport), ("anthropic", AnthropicTransport)],
)
def test_missing_added_model_key_never_displays_variable(
    monkeypatch: pytest.MonkeyPatch,
    template: str,
    transport_class: type[ChatCompletionsTransport] | type[AnthropicTransport],
) -> None:
    monkeypatch.delenv("DEVSEC_KEY_CUSTOM", raising=False)
    profile = BUILTIN_PROFILES[template].model_copy(
        update={"id": "custom", "api_key_env": "DEVSEC_KEY_CUSTOM"}
    )
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(500))) as client:
        transport = transport_class(profile, "test", http=client)
        with pytest.raises(ProviderError) as error:
            transport.complete("test", [], [])
    assert "DEVSEC_KEY_" not in str(error.value)
    assert "custom" in str(error.value) and "key" in str(error.value).lower()


@pytest.mark.parametrize("transport_class", [ChatCompletionsTransport, AnthropicTransport])
def test_added_local_model_without_key_can_call_transport(monkeypatch, transport_class) -> None:
    monkeypatch.delenv("DEVSEC_KEY_LOCAL", raising=False)
    profile = BUILTIN_PROFILES["ollama"].model_copy(
        update={"id": "local", "api_key_env": "DEVSEC_KEY_LOCAL"}
    )
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "content": [{"type": "text", "text": "ok"}],
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        reply = transport_class(profile, "fixture", http=client).complete("test", [], [])
    assert reply.message.content == "ok"
    assert "Authorization" not in seen[0].headers
    assert "x-api-key" not in seen[0].headers
