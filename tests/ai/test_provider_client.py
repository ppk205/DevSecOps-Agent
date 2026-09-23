"""T04 gate: provider client — mocked Chat Completions HTTP."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from vulnscan.contracts.provider import ProviderProfile
from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.providers.client import ProviderClient, ChatMessage, ProviderError
from vulnscan.providers.budget import BudgetManager


def _profile(**overrides) -> ProviderProfile:
    defaults = dict(
        id="test-prov",
        label="Test Provider",
        protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        base_url="https://api.example.com/v1",
        api_key_env="TEST_API_KEY",
        models=["gpt-4o"],
        default_model="gpt-4o",
        timeout_seconds=30,
    )
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

    def test_missing_api_key(self):
        """Missing env var raises CredentialError."""
        with patch.dict("os.environ", {}, clear=True):
            client = ProviderClient(_profile())
            with pytest.raises(Exception, match="TEST_API_KEY"):
                client.chat([ChatMessage(role="user", content="hi")])

    def test_budget_enforcement(self):
        """Budget exhaustion prevents the request."""
        bm = BudgetManager(total_usd=-1.0, reserve_usd=0.0)
        with patch.dict("os.environ", {"TEST_API_KEY": "sk-test123456789"}):
            client = ProviderClient(_profile(), budget=bm)
            from vulnscan.providers.budget import BudgetExhausted
            with pytest.raises(BudgetExhausted):
                client.chat([ChatMessage(role="user", content="hi")])
