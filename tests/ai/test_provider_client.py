"""T04 gate: provider client — mocked Chat Completions HTTP."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.providers.budget import BudgetExhausted, BudgetManager
from vulnscan.providers.client import (
    ChatMessage,
    ProviderClient,
    _extract_v0_tool_calls,
    _make_http_client,
)
from vulnscan.providers.credentials import CredentialError
from vulnscan.providers.events import model_progress
from vulnscan.scanners.process import ScanCancelled


def _profile(**overrides) -> ProviderProfile:
    defaults = {
        "id": "test-prov",
        "label": "Test Provider",
        "protocol": ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        "base_url": "https://api.example.com/v1",
        "api_key_env": "TEST_API_KEY",
        "models": ["gpt-4o"],
        "default_model": "gpt-4o",
        "timeout_seconds": 30,
    }
    defaults.update(overrides)
    return ProviderProfile(**defaults)


class TestProviderClient:
    def test_chat_success(self):
        """Mock HTTP response and verify parsing."""
        resp_data = {
            "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "model": "gpt-4o",
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = resp_data
        mock_resp.raise_for_status = MagicMock()

        with patch("vulnscan.providers.client.httpx.Client") as MockClient:
            mock_client = MockClient.return_value.__enter__.return_value
            mock_client.post.return_value = mock_resp

            with patch.dict("os.environ", {"TEST_API_KEY": "sk-test123456789"}):
                client = ProviderClient(_profile())
                resp = client.chat([ChatMessage(role="user", content="hi")])

        assert resp.content == "hello"
        assert resp.model == "gpt-4o"
        assert resp.usage["total_tokens"] == 15

    def test_openai_serializes_tool_calls_and_tool_call_id(self):
        """OpenAI payload preserves assistant tool_calls and tool role tool_call_id."""
        resp_data = {
            "choices": [{"message": {"content": "done"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 4, "total_tokens": 24},
            "model": "gpt-4o",
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = resp_data
        mock_resp.raise_for_status = MagicMock()

        tc = [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "run_semgrep_scan", "arguments": "{}"},
            }
        ]
        with patch("vulnscan.providers.client.httpx.Client") as MockClient:
            mock_client = MockClient.return_value.__enter__.return_value
            mock_client.post.return_value = mock_resp

            with patch.dict("os.environ", {"TEST_API_KEY": "sk-test123456789"}):
                client = ProviderClient(_profile())
                client.chat(
                    [
                        ChatMessage(role="user", content="scan"),
                        ChatMessage(role="assistant", content="", tool_calls=tc),
                        ChatMessage(role="tool", content='{"ok": true}', tool_call_id="call_1"),
                    ]
                )

            sent_payload = mock_client.post.call_args.kwargs["json"]
            assert sent_payload["messages"][1]["tool_calls"] == tc
            assert sent_payload["messages"][2]["tool_call_id"] == "call_1"

    def test_missing_api_key(self):
        """Missing env var raises CredentialError."""
        budget = BudgetManager(max_requests=0)
        with patch.dict("os.environ", {}, clear=True):
            client = ProviderClient(_profile(), budget=budget)
            with pytest.raises(CredentialError, match="TEST_API_KEY"):
                client.chat([ChatMessage(role="user", content="hi")])
        assert budget.attempts == 0

    def test_budget_enforcement(self):
        """Budget exhaustion prevents the request."""
        bm = BudgetManager(total_usd=-1.0, reserve_usd=0.0)
        with patch.dict("os.environ", {"TEST_API_KEY": "sk-test123456789"}):
            client = ProviderClient(_profile(), budget=bm)
            with pytest.raises(BudgetExhausted):
                client.chat([ChatMessage(role="user", content="hi")])


@pytest.mark.parametrize("retry_v0", [False, True])
@pytest.mark.parametrize("max_requests", [2, 3])
def test_provider_request_limit_counts_retries_across_models_and_protocols(
    monkeypatch, retry_v0, max_requests
):
    budget = BudgetManager(max_requests=max_requests)
    monkeypatch.setenv("TEST_API_KEY", "synthetic-key")
    sent_paths = []

    def respond(request: httpx.Request) -> httpx.Response:
        sent_paths.append(request.url.path)
        if len(sent_paths) == 2:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}], "text": "ok"},
        )

    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(
        "vulnscan.providers.client._make_http_client",
        lambda timeout: httpx.Client(transport=transport, timeout=timeout),
    )
    openai = ProviderClient(_profile(), budget=budget)
    v0 = ProviderClient(
        _profile(id="v0-test", protocol=ProviderProtocol.V0_PLATFORM_API), budget=budget
    )
    first, retried = (openai, v0) if retry_v0 else (v0, openai)
    messages = [ChatMessage(role="user", content="hi")]

    assert first.chat(messages, model="first-model").content == "ok"
    if max_requests == 2:
        with pytest.raises(BudgetExhausted):
            retried.chat(messages, model="second-model")
    else:
        assert retried.chat(messages, model="second-model").content == "ok"
    with pytest.raises(BudgetExhausted):
        first.chat(messages, model="third-model")

    chat, v0_chat = "/v1/chat/completions", "/v1/chats"
    first_path, retry_path = (chat, v0_chat) if retry_v0 else (v0_chat, chat)
    assert sent_paths == [first_path] + [retry_path] * (max_requests - 1)
    assert budget.attempts == max_requests
    assert budget.max_requests == max_requests


def test_cancelled_before_provider_post_leaves_request_slot_available(monkeypatch):
    budget = BudgetManager(max_requests=1)
    monkeypatch.setenv("TEST_API_KEY", "synthetic-key")
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(
        "vulnscan.providers.client._make_http_client",
        lambda timeout: httpx.Client(transport=transport, timeout=timeout),
    )
    client = ProviderClient(_profile(), budget=budget)
    messages = [ChatMessage(role="user", content="hi")]

    def cancel_before_post(event):
        if event["status"] == "running":
            raise ScanCancelled()

    token = model_progress.set(cancel_before_post)
    try:
        with pytest.raises(ScanCancelled):
            client.chat(messages)
    finally:
        model_progress.reset(token)

    assert requests == []
    assert budget.attempts == 0
    assert client.chat(messages).content == "ok"
    assert len(requests) == budget.attempts == 1


class TestV0PlatformClient:
    def test_v0_auto_detect_and_tool_call_roundtrip(self):
        """v0 Platform API creates a chat, parses tool calls, reuses chatId, and cleans up."""
        turn1_resp = MagicMock()
        turn1_resp.status_code = 200
        turn1_resp.raise_for_status = MagicMock()
        turn1_resp.json.return_value = {
            "id": "chat_abc123",
            "modelConfiguration": {"modelId": "v0-mini"},
            "messages": [
                {"role": "user", "content": "scan app.py"},
                {
                    "role": "assistant",
                    "content": json.dumps(
                        {
                            "tool_calls": [
                                {
                                    "name": "run_semgrep_scan",
                                    "arguments": {"target_path": "app.py"},
                                }
                            ]
                        }
                    ),
                    "finishReason": "stop",
                },
            ],
        }

        turn2_resp = MagicMock()
        turn2_resp.status_code = 200
        turn2_resp.raise_for_status = MagicMock()
        turn2_resp.json.return_value = {
            "id": "chat_abc123",
            "echo": "v1:team_x:vcp_secret",
            "modelConfiguration": {"modelId": "v0-mini"},
            "messages": [
                {
                    "role": "assistant",
                    "content": '{"proposed_status": "confirmed", "confidence": 0.95}',
                    "finishReason": "stop",
                }
            ],
        }

        del_resp = MagicMock()
        del_resp.status_code = 200

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "run_semgrep_scan",
                    "description": "Run Semgrep SAST",
                    "parameters": {
                        "type": "object",
                        "properties": {"target_path": {"type": "string"}},
                    },
                },
            }
        ]

        profile = _profile(
            id="v0-main",
            protocol=ProviderProtocol.OPENAI_COMPATIBLE,
            base_url="https://api.v0.dev/v1",
            api_key_env="V0_API_KEY",
            models=["v0-mini"],
            default_model="v0-mini",
            metadata={"ephemeral_chats": True},
        )

        with patch("vulnscan.providers.client.httpx.Client") as MockClient:
            mock_client = MockClient.return_value.__enter__.return_value
            mock_client.post.side_effect = [turn1_resp, turn2_resp]
            mock_client.delete.return_value = del_resp

            with patch.dict("os.environ", {"V0_API_KEY": "v1:team_x:vcp_secret"}):
                client = ProviderClient(profile)
                messages = [
                    ChatMessage(role="system", content="You are a security analyst."),
                    ChatMessage(role="user", content="scan app.py v1:team_x:vcp_secret"),
                ]
                r1 = client.chat(messages, tools=tools)
                assert r1.finish_reason == "tool_calls"
                assert len(r1.tool_calls) == 1
                assert r1.tool_calls[0]["function"]["name"] == "run_semgrep_scan"
                assert mock_client.post.call_args_list[0].args[0] == "https://api.v0.dev/v1/chats"
                assert (
                    "vcp_secret" not in mock_client.post.call_args_list[0].kwargs["json"]["message"]
                )

                messages.append(ChatMessage(role="assistant", content="", tool_calls=r1.tool_calls))
                messages.append(
                    ChatMessage(
                        role="tool",
                        content='{"total_findings": 1}',
                        tool_call_id=r1.tool_calls[0]["id"],
                    )
                )
                r2 = client.chat(messages, tools=tools)
                assert r2.tool_calls == []
                assert "confirmed" in r2.content
                assert "vcp_secret" not in r2.raw["echo"]
                assert (
                    mock_client.post.call_args_list[1].args[0]
                    == "https://api.v0.dev/v1/chats/chat_abc123/messages"
                )
                # ephemeral_chats deletes the remote chat after final response
                mock_client.delete.assert_called_once()
                assert (
                    mock_client.delete.call_args.args[0]
                    == "https://api.v0.dev/v1/chats/chat_abc123"
                )

    def test_extract_v0_tool_calls_handles_fences_and_ignores_unknown_tools(self):
        fenced = '```json\n{"tool_calls": [{"name": "inspect_code", "arguments": {"path": "a.py"}}, {"name": "evil_tool", "arguments": {}}]}\n```'
        calls = _extract_v0_tool_calls(fenced, {"inspect_code"})
        assert len(calls) == 1
        assert calls[0]["function"]["name"] == "inspect_code"
        assert json.loads(calls[0]["function"]["arguments"]) == {"path": "a.py"}

    def test_make_http_client_falls_back_on_invalid_ipv6_no_proxy(self):
        """Ensure _make_http_client succeeds even when NO_PROXY has bare ::1,[::1]."""
        with patch.dict(
            "os.environ",
            {
                "NO_PROXY": "localhost,127.0.0.1,::1,[::1]",
                "no_proxy": "localhost,127.0.0.1,::1,[::1]",
            },
        ):
            client = _make_http_client(10)
            assert isinstance(client, httpx.Client)
            client.close()
