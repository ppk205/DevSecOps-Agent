"""Provider profiles and the two harness transports."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.harness.messages import Message, ProviderError, ToolCall
from vulnscan.harness.providers import (
    BUILTIN_PROFILES,
    AnthropicTransport,
    ChatCompletionsTransport,
    all_profiles,
    is_local,
    make_transport,
)
from vulnscan.providers.profile_store import save_profile

HISTORY = [
    Message("user", "scan"),
    Message("assistant", "", [ToolCall("c1", "inventory", {"globs": ["**/*.java"]})]),
    Message("tool", '{"ok":true}', tool_call_id="c1", name="inventory"),
    Message("tool", '{"ok":2}', tool_call_id="c2", name="grep"),
]


def test_chat_completions_round_trips_tool_calls() -> None:
    wire = ChatCompletionsTransport.to_wire("SYS", HISTORY[:3])
    assert wire[0] == {"role": "system", "content": "SYS"}
    assert wire[2]["tool_calls"][0]["function"] == {
        "name": "inventory",
        "arguments": '{"globs": ["**/*.java"]}',
    }
    assert wire[3] == {"role": "tool", "tool_call_id": "c1", "content": '{"ok":true}'}


def test_chat_completions_keeps_unparseable_arguments() -> None:
    msg, stop = ChatCompletionsTransport.from_wire(
        {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"id": "x", "function": {"name": "grep", "arguments": "{bad"}}
                        ]
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        }
    )
    assert msg.tool_calls[0].arguments == {"_unparsed": "{bad"} and stop == "tool_calls"


def test_anthropic_groups_consecutive_tool_results() -> None:
    wire = AnthropicTransport.to_wire(HISTORY)
    assert wire[1]["content"][0] == {
        "type": "tool_use",
        "id": "c1",
        "name": "inventory",
        "input": {"globs": ["**/*.java"]},
    }
    assert [b["tool_use_id"] for b in wire[2]["content"]] == ["c1", "c2"]


def test_anthropic_from_wire_reads_text_and_tool_use() -> None:
    msg = AnthropicTransport.from_wire(
        {
            "content": [
                {"type": "text", "text": "hi"},
                {"type": "tool_use", "id": "t", "name": "grep", "input": {"pattern": "x"}},
            ]
        }
    )
    assert msg.content == "hi" and msg.tool_calls[0].arguments == {"pattern": "x"}


def _mock(responses: list[httpx.Response], seen: list[httpx.Request]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responses.pop(0)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_complete_sends_bearer_and_reads_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    seen: list[httpx.Request] = []
    ok = httpx.Response(
        200,
        json={
            "model": "deepseek-chat",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            "choices": [{"message": {"content": "done"}, "finish_reason": "stop"}],
        },
    )
    t = ChatCompletionsTransport(
        BUILTIN_PROFILES["deepseek"], "deepseek-chat", http=_mock([ok], seen)
    )
    reply = t.complete("SYS", [Message("user", "hi")], [])
    assert seen[0].headers["Authorization"] == "Bearer k" and seen[0].url.path.endswith(
        "/chat/completions"
    )
    assert (reply.usage.input_tokens, reply.usage.output_tokens, reply.message.content) == (
        10,
        5,
        "done",
    )


def test_local_profile_sends_no_auth_header() -> None:
    seen: list[httpx.Request] = []
    ok = httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})
    ChatCompletionsTransport(BUILTIN_PROFILES["ollama"], "llama3", http=_mock([ok], seen)).complete(
        "S", [], []
    )
    assert "Authorization" not in seen[0].headers and is_local(BUILTIN_PROFILES["ollama"])


def test_missing_key_raises_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(ProviderError):
        ChatCompletionsTransport(
            BUILTIN_PROFILES["deepseek"], "deepseek-chat", http=_mock([], [])
        ).complete("S", [], [])


def test_retries_429_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    monkeypatch.setattr("vulnscan.harness.providers.time.sleep", lambda s: None)
    ok = httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})
    seen: list[httpx.Request] = []
    t = ChatCompletionsTransport(
        BUILTIN_PROFILES["deepseek"], "deepseek-chat", http=_mock([httpx.Response(429), ok], seen)
    )
    assert t.complete("S", [], []).message.content == "x" and len(seen) == 2


def test_user_profile_overrides_builtin(tmp_path: Any) -> None:
    save_profile(
        ProviderProfile(
            id="deepseek",
            label="DS",
            protocol=ProviderProtocol.OPENAI_COMPATIBLE,
            base_url="https://api.deepseek.com",
            api_key_env="DEEPSEEK_API_KEY",
            default_model="deepseek-reasoner",
        ),
        tmp_path,
    )
    assert all_profiles(tmp_path)["deepseek"].default_model == "deepseek-reasoner"


def test_make_transport_needs_a_model() -> None:
    with pytest.raises(ProviderError):
        make_transport(BUILTIN_PROFILES["openai"])
    assert isinstance(make_transport(BUILTIN_PROFILES["anthropic"]), AnthropicTransport)
