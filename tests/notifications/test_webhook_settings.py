"""FR-75 / P-WEB-01/02: offline, reference-only v2 settings and v1 migration."""

import json
import socket
from pathlib import Path

import pytest

from vulnscan.infra.envfile import EnvFile
from vulnscan.notifications import settings as notification_settings
from vulnscan.notifications.settings import NotificationSettings, load_settings, save_settings
from vulnscan.providers import credentials


@pytest.mark.parametrize("mode", ["manual", "automatic"])
def test_v1_upgrades_without_enabling_webhook(tmp_path, mode):
    original = {
        "schema_version": 1,
        "mode": mode,
        "telegram": {
            "enabled": True,
            "events": ["scan_failed", "gate_failed"],
            "token_env": "CUSTOM_TELEGRAM_TOKEN",
            "chat_env": "CUSTOM_TELEGRAM_CHAT",
        },
        "discord": {
            "enabled": True,
            "events": ["report_ready", "scan_completed"],
            "webhook_env": "CUSTOM_DISCORD_SECRET",
        },
    }
    path = tmp_path / ".devsec-notifications.json"
    before = json.dumps(original).encode()
    path.write_bytes(before)

    cfg = load_settings(base=tmp_path)
    assert cfg.schema_version == 2
    assert cfg.mode == mode
    assert cfg.telegram.model_dump() == original["telegram"]
    assert cfg.discord.model_dump() == original["discord"]
    assert cfg.webhook.enabled is False and cfg.webhook.events == []
    assert path.read_bytes() == before  # Migration on read does not write.

    save_settings(cfg, base=tmp_path)
    saved = json.loads(path.read_bytes())
    assert saved["schema_version"] == 2
    assert saved["telegram"] == original["telegram"]
    assert saved["discord"] == original["discord"]
    assert load_settings(base=tmp_path) == cfg


def test_default_references_and_no_host_are_off(tmp_path):
    cfg = load_settings(base=tmp_path)
    assert cfg.schema_version == 2
    assert cfg.mode == "manual"
    assert cfg.webhook.enabled is False and cfg.webhook.events == []
    assert cfg.webhook.url_env == "DEVSEC_WEBHOOK_URL"
    assert cfg.webhook.signing_key_env == "DEVSEC_WEBHOOK_SIGNING_SECRET"
    assert cfg.webhook.allowed_hosts == []


def test_unversioned_partial_update_still_uses_defaults(tmp_path):
    cfg = save_settings({"discord": {"events": ["gate_failed"]}}, base=tmp_path)
    assert cfg.schema_version == 2
    assert cfg.discord.events == ["gate_failed"]
    assert not cfg.discord.enabled
    assert not cfg.telegram.enabled and cfg.telegram.events == []
    assert not cfg.webhook.enabled and cfg.webhook.events == []


def test_hosts_and_events_are_normalized_and_deduplicated(tmp_path):
    cfg = save_settings(
        {
            "schema_version": 2,
            "webhook": {
                "enabled": True,
                "events": ["gate_failed", "gate_failed", "report_ready"],
                "url_env": "CUSTOM_WEBHOOK_URL",
                "signing_key_env": "CUSTOM_WEBHOOK_SECRET",
                "allowed_hosts": ["Hooks.Example.COM.", "hooks.example.com", "BÜCHER.Example."],
            },
        },
        base=tmp_path,
    )
    assert cfg.webhook.allowed_hosts == ["hooks.example.com", "xn--bcher-kva.example"]
    assert cfg.webhook.events == ["gate_failed", "report_ready"]
    assert cfg.webhook.url_env == "CUSTOM_WEBHOOK_URL"
    assert cfg.webhook.signing_key_env == "CUSTOM_WEBHOOK_SECRET"
    assert load_settings(base=tmp_path) == cfg


def test_enabled_webhook_requires_an_explicit_host(tmp_path):
    with pytest.raises(ValueError, match="^Invalid notification settings$"):
        save_settings({"webhook": {"enabled": True}}, base=tmp_path)
    assert not (tmp_path / ".devsec-notifications.json").exists()


@pytest.mark.parametrize(
    "host",
    [
        "*.example.com",
        "hooks.example.com\n",
        "hooks.example.com\x00",
        "hooks.example.com\x7f",
        "hooks.\u200bexample.com",
        " hooks.example.com",
        "hooks.example.com:443",
        "https://hooks.example.com/synthetic-private-url",
        "user@hooks.example.com",
        "hooks.example.com/path",
        "hooks.example.com?token=synthetic-private-token",
        "bad_name.example.com",
        "-bad.example.com",
        "bad-.example.com",
        "hooks..example.com",
        "",
        ".",
        "xn--a.example",
        "127.0.0.1",
        "::1",
        "[::1]",
        "a" * 64 + ".example.com",
        ".".join(["a" * 63] * 4),
    ],
)
def test_invalid_hosts_are_rejected_even_when_disabled(tmp_path, host):
    with pytest.raises(ValueError, match="^Invalid notification settings$") as error:
        save_settings({"webhook": {"allowed_hosts": [host]}}, base=tmp_path)
    if host:
        assert host not in str(error.value)


@pytest.mark.parametrize("reference", ["url_env", "signing_key_env"])
@pytest.mark.parametrize(
    "value", ["https://hooks.example.com/synthetic-private-url", "synthetic-private-key!"]
)
def test_pasted_credentials_are_rejected_without_echo(tmp_path, reference, value):
    with pytest.raises(ValueError, match="^Invalid notification settings$") as error:
        save_settings({"webhook": {reference: value}}, base=tmp_path)
    assert value not in str(error.value)

    # Direct model validation must also keep input out of its display error.
    with pytest.raises(ValueError) as error:
        notification_settings.WebhookSettings.model_validate({reference: value})
    assert value not in str(error.value)


@pytest.mark.parametrize("version", [3, 0, "2", None, True, 2.0])
def test_unsupported_versions_fail_on_load_and_save(tmp_path, version):
    path = tmp_path / ".devsec-notifications.json"
    path.write_text(json.dumps({"schema_version": version}))
    with pytest.raises(ValueError, match="^Invalid notification settings$"):
        load_settings(base=tmp_path)
    with pytest.raises(ValueError, match="^Invalid notification settings$"):
        save_settings({"schema_version": version}, base=tmp_path)


def test_v1_cannot_enable_an_injected_webhook(tmp_path):
    cfg = save_settings(
        {"schema_version": 1, "webhook": {"enabled": True, "allowed_hosts": ["example.com"]}},
        base=tmp_path,
    )
    assert cfg.schema_version == 2
    assert not cfg.webhook.enabled and cfg.webhook.events == []


def test_unknown_event_and_extra_credential_fields_are_rejected(tmp_path):
    for webhook in ({"events": ["pr_created"]}, {"url": "synthetic-private-url"}):
        with pytest.raises(ValueError, match="^Invalid notification settings$"):
            save_settings({"webhook": webhook}, base=tmp_path)


def test_failed_atomic_replace_keeps_previous_settings(tmp_path, monkeypatch):
    path = tmp_path / ".devsec-notifications.json"
    save_settings({"telegram": {"events": ["scan_failed"]}}, base=tmp_path)
    before = path.read_bytes()

    def failed_replace(source, destination):
        assert Path(destination) == path
        assert Path(source).parent == path.parent
        assert json.loads(Path(source).read_bytes())["schema_version"] == 2
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(notification_settings.os, "replace", failed_replace)
    with pytest.raises(OSError, match="synthetic replace failure"):
        save_settings({"mode": "automatic"}, base=tmp_path)
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]


def test_load_save_and_validation_have_no_external_side_effects(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Settings must not load credentials, resolve DNS, or send HTTP")

    monkeypatch.setattr(EnvFile, "load_into_environ", forbidden)
    monkeypatch.setattr(credentials, "load_api_key", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(notification_settings.os, "environ", {})
    cfg = save_settings(
        {"webhook": {"enabled": True, "allowed_hosts": ["hooks.example.com"]}}, base=tmp_path
    )
    assert load_settings(base=tmp_path) == cfg
    assert cfg.webhook.enabled and cfg.webhook.events == []


def test_webhook_lists_are_not_shared_between_settings():
    first = NotificationSettings()
    second = NotificationSettings()
    first.webhook.allowed_hosts.append("hooks.example.com")
    first.webhook.events.append("gate_failed")
    assert second.webhook.allowed_hosts == [] and second.webhook.events == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("url_env", "https://hooks.example.com/synthetic-private-url"),
        ("signing_key_env", "synthetic-private-key!"),
        ("allowed_hosts", ["*.example.com"]),
        ("enabled", True),
    ],
)
def test_save_revalidates_mutated_model_before_writing(tmp_path, field, value):
    cfg = NotificationSettings()
    setattr(cfg.webhook, field, value)
    with pytest.raises(ValueError, match="^Invalid notification settings$") as error:
        save_settings(cfg, base=tmp_path)
    assert "synthetic-private" not in str(error.value)
    assert not (tmp_path / ".devsec-notifications.json").exists()


def test_save_revalidates_mutated_schema_version(tmp_path):
    cfg = NotificationSettings()
    cfg.schema_version = 3
    with pytest.raises(ValueError, match="^Invalid notification settings$"):
        save_settings(cfg, base=tmp_path)
    assert not (tmp_path / ".devsec-notifications.json").exists()
