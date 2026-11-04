"""FR-48/49, IR-12: provider explanations and complete investigation messages."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from tests.ai.test_provider_client import _profile
from tests.ai.test_review_wiring import _finding
from vulnscan.agent.loop import AgentLoop
from vulnscan.providers.client import ChatMessage, ChatResponse, ProviderClient, ProviderError
from vulnscan.providers.events import model_progress


def test_fr48_provider_preserves_explanation_alongside_final_answer():
    response = MagicMock()
    response.json.return_value = {
        "choices": [
            {"message": {"content": "final answer", "reasoning_content": "returned explanation"}}
        ]
    }
    with (
        patch("vulnscan.providers.client.httpx.Client") as transport,
        patch.object(ProviderClient, "_get_key", return_value="synthetic-credential"),
    ):
        transport.return_value.__enter__.return_value.post.return_value = response
        reply = ProviderClient(_profile()).chat([ChatMessage("user", "synthetic input")])
    assert reply.content == "final answer"
    assert reply.reasoning == "returned explanation"


def test_fr48_tool_round_trip_keeps_tool_call_ids_in_http_messages():
    response = MagicMock()
    response.json.return_value = {"choices": [{"message": {"content": "answer"}}]}
    calls = [
        {
            "id": "call-1",
            "type": "function",
            "function": {"name": "inspect_code", "arguments": "{}"},
        }
    ]
    messages = [
        ChatMessage("assistant", "", tool_calls=calls),
        ChatMessage("tool", '{"lines": []}', tool_call_id="call-1"),
    ]
    with (
        patch("vulnscan.providers.client.httpx.Client") as transport,
        patch.object(ProviderClient, "_get_key", return_value="synthetic-credential"),
    ):
        client = transport.return_value.__enter__.return_value
        client.post.return_value = response
        ProviderClient(_profile()).chat(messages)
        sent = client.post.call_args.kwargs["json"]["messages"]
    assert sent[0]["tool_calls"] == calls
    assert sent[1]["tool_call_id"] == "call-1"


def test_fr48_investigation_calls_the_selected_model():
    client = MagicMock()
    client.chat.return_value = ChatResponse(
        content='{"proposed_status":"unresolved","confidence":0.5,"rationale":"Evidence needs review"}'
    )
    AgentLoop(client, {}, model_id="selected-model").investigate(_finding(), {})
    assert client.chat.call_args.kwargs["model"] == "selected-model"


def test_fr48_investigation_without_an_override_keeps_provider_default():
    client = MagicMock()
    client.chat.return_value = ChatResponse(
        content='{"proposed_status":"unresolved","rationale":"Review needed"}'
    )
    AgentLoop(client, {}).investigate(_finding(), {})
    assert client.chat.call_args.kwargs["model"] is None


def test_fr48_review_uses_the_first_profile_model_when_no_default_is_named(monkeypatch):
    from vulnscan.ai import review

    monkeypatch.setattr(
        review, "load_profile", lambda _: _profile(default_model=None, models=["first-model"])
    )
    loop, _, _, _ = review.build_review_agent("test-prov", {})
    assert loop.model_id == "first-model"


def test_fr49_call_progress_redacts_explanations_and_reports_actual_usage():
    response = MagicMock()
    response.json.return_value = {
        "choices": [
            {"message": {"content": "answer", "reasoning_content": "echo synthetic-credential"}}
        ],
        "model": "reported-model",
        "usage": {"total_tokens": 17},
    }
    events = []
    token = model_progress.set(events.append)
    try:
        with (
            patch("vulnscan.providers.client.httpx.Client") as transport,
            patch.object(ProviderClient, "_get_key", return_value="synthetic-credential"),
        ):
            transport.return_value.__enter__.return_value.post.return_value = response
            result = ProviderClient(_profile()).chat([ChatMessage("user", "input")])
    finally:
        model_progress.reset(token)
    assert [e["status"] for e in events] == ["running", "completed"]
    assert events[-1]["model"] == "reported-model"
    assert events[-1]["usage"]["total_tokens"] == 17
    assert "synthetic-credential" not in str(events) + result.reasoning
    assert "[REDACTED]" in result.reasoning


def test_fr49_failed_http_call_is_never_reported_as_completed():
    request = httpx.Request("POST", "https://offline.invalid/v1/chat/completions")
    response = httpx.Response(503, request=request)
    events = []
    token = model_progress.set(events.append)
    try:
        with (
            patch("vulnscan.providers.client.httpx.Client") as transport,
            patch.object(ProviderClient, "_get_key", return_value="synthetic-credential"),
        ):
            transport.return_value.__enter__.return_value.post.side_effect = httpx.HTTPStatusError(
                "offline failure", request=request, response=response
            )
            with pytest.raises(ProviderError):
                ProviderClient(_profile(max_retries=0)).chat([ChatMessage("user", "input")])
    finally:
        model_progress.reset(token)
    assert [e["status"] for e in events] == ["running", "failed"]
    assert events[-1]["usage"] == {}


def test_fr49_final_report_does_not_label_missing_usage_as_zero(monkeypatch):
    from vulnscan.reporting import final_report

    client = MagicMock()
    client.chat.return_value = ChatResponse(content="A returned explanation", model="test-model")
    monkeypatch.setattr(final_report, "load_profile", lambda _: _profile())
    monkeypatch.setattr(final_report, "ProviderClient", lambda *args: client)
    result = final_report.run_final_report([], [], {}, profile_id="test-prov")
    assert result["status"] == "completed"
    assert "unavailable" in result["detail"]
