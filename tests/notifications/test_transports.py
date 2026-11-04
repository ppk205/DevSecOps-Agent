"""FR-75: channel payloads, acknowledgements and secret-safe failures."""

from urllib.error import URLError

import pytest

from vulnscan.notifications import transports


def test_telegram_uses_bot_api_and_requires_an_ack(monkeypatch):
    seen = []
    monkeypatch.setenv("TEST_BOT_TOKEN", "123456:synthetic-token")
    monkeypatch.setenv("TEST_CHAT_ID", "-100123456")

    def post(url, payload, timeout):
        seen.append((url, payload))
        return 200, {"ok": True, "result": {"message_id": 1}}

    monkeypatch.setattr(transports, "_post_json", post)
    result = transports.send_telegram(
        "Scan summary", token_env="TEST_BOT_TOKEN", chat_env="TEST_CHAT_ID"
    )
    assert result.status == "sent"
    assert seen[0][0].endswith("/bot123456:synthetic-token/sendMessage")
    assert seen[0][1]["chat_id"] == "-100123456"
    assert "parse_mode" not in seen[0][1]
    monkeypatch.setattr(
        transports, "_post_json", lambda *args: (200, {"ok": False, "error_code": 401})
    )
    assert (
        transports.send_telegram(
            "Summary", token_env="TEST_BOT_TOKEN", chat_env="TEST_CHAT_ID"
        ).status
        == "failed"
    )


def test_discord_waits_for_confirmation_and_disables_mentions(monkeypatch):
    seen = []
    monkeypatch.setenv(
        "TEST_WEBHOOK_SECRET", "https://discord.com/api/webhooks/123456/synthetic-webhook"
    )

    def post(url, payload, timeout):
        seen.append((url, payload))
        return 200, {"id": "message-id"}

    monkeypatch.setattr(transports, "_post_json", post)
    result = transports.send_discord("@everyone scan completed", webhook_env="TEST_WEBHOOK_SECRET")
    assert result.status == "sent"
    assert "wait=true" in seen[0][0]
    assert seen[0][1]["allowed_mentions"] == {"parse": []}


@pytest.mark.parametrize(
    "url",
    [
        "http://discord.com/api/webhooks/1/token",
        "https://example.test/hook",
        "https://discord.com.evil.test/api/webhooks/1/token",
        "https://user:pass@discord.com/api/webhooks/1/token",
    ],
)
def test_discord_rejects_untrusted_destinations_before_network(monkeypatch, url):
    monkeypatch.setenv("TEST_WEBHOOK_SECRET", url)
    monkeypatch.setattr(transports, "_post_json", lambda *args: pytest.fail("network must not run"))
    assert (
        transports.send_discord("Summary", webhook_env="TEST_WEBHOOK_SECRET").status
        == "unconfigured"
    )


def test_missing_credentials_do_not_make_requests(monkeypatch):
    monkeypatch.delenv("TEST_ABSENT_BOT", raising=False)
    monkeypatch.setattr(transports, "_post_json", lambda *args: pytest.fail("network must not run"))
    assert (
        transports.send_telegram(
            "Summary", token_env="TEST_ABSENT_BOT", chat_env="TEST_ABSENT_CHAT"
        ).status
        == "unconfigured"
    )


def test_transport_errors_do_not_echo_tokens_or_claim_delivery(monkeypatch):
    monkeypatch.setenv(
        "TEST_WEBHOOK_SECRET", "https://discord.com/api/webhooks/123456/synthetic-webhook"
    )

    def fail(*args):
        raise URLError("synthetic-webhook")

    monkeypatch.setattr(transports, "_post_json", fail)
    result = transports.send_discord("Summary", webhook_env="TEST_WEBHOOK_SECRET")
    assert result.status != "sent"
    assert "synthetic-webhook" not in result.detail


def test_http_success_without_provider_ack_is_unknown(monkeypatch):
    monkeypatch.setenv(
        "TEST_WEBHOOK_SECRET", "https://discord.com/api/webhooks/123456/synthetic-webhook"
    )
    monkeypatch.setattr(transports, "_post_json", lambda *args: (204, {}))
    assert transports.send_discord("Summary", webhook_env="TEST_WEBHOOK_SECRET").status == "unknown"


def test_outbound_messages_keep_existing_display_sanitization(monkeypatch):
    seen = []
    monkeypatch.setenv(
        "TEST_WEBHOOK_SECRET", "https://discord.com/api/webhooks/123456/synthetic-webhook"
    )
    monkeypatch.setattr(
        transports,
        "_post_json",
        lambda url, payload, timeout: seen.append(payload) or (200, {"id": "message"}),
    )
    transports.send_discord("\x1b[31mScan completed\x1b[0m", webhook_env="TEST_WEBHOOK_SECRET")
    assert seen[0]["content"] == "Scan completed"


@pytest.mark.parametrize("message_id", [False, "unexpected", {"invalid": "shape"}])
def test_malformed_telegram_ack_does_not_claim_sent(monkeypatch, message_id):
    monkeypatch.setenv("TEST_BOT_TOKEN", "123456:synthetic-token")
    monkeypatch.setenv("TEST_CHAT_ID", "-100123456")
    monkeypatch.setattr(
        transports,
        "_post_json",
        lambda *args: (200, {"ok": True, "result": {"message_id": message_id}}),
    )
    assert (
        transports.send_telegram(
            "Summary", token_env="TEST_BOT_TOKEN", chat_env="TEST_CHAT_ID"
        ).status
        == "unknown"
    )


def test_malformed_discord_ack_does_not_claim_sent(monkeypatch):
    monkeypatch.setenv(
        "TEST_WEBHOOK_SECRET", "https://discord.com/api/webhooks/123456/synthetic-webhook"
    )
    monkeypatch.setattr(transports, "_post_json", lambda *args: (200, {"id": {"invalid": "shape"}}))
    assert transports.send_discord("Summary", webhook_env="TEST_WEBHOOK_SECRET").status == "unknown"
