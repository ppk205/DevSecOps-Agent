"""FR-75: human-facing interfaces choose events, never expose destinations."""

import json
import threading

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from tests.platform.test_scan_service import checkout, service
from vulnscan.cli.main import app
from vulnscan.core.rpc import ServiceRPC
from vulnscan.notifications.settings import load_settings
from vulnscan.web.app import create_app

__all__ = ["checkout", "service"]


def test_cli_setup_asks_which_events_to_send(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").touch()
    result = CliRunner().invoke(app, ["notifications", "configure"], input="manual\ny\ny\n1,4\n1\n")
    assert result.exit_code == 0, result.output
    cfg = load_settings()
    assert cfg.mode == "manual" and cfg.telegram.enabled and cfg.discord.enabled
    assert cfg.telegram.events == ["scan_completed", "gate_failed"]
    assert cfg.discord.events == ["scan_completed"]
    assert "Which events" in result.output


def test_rpc_settings_save_rejects_values_without_echo(service, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").touch()
    rpc = ServiceRPC(service)
    result = rpc.dispatch("notification", {"action": "settings"}, "n", threading.Event())
    assert result["settings"]["telegram"]["enabled"] is False
    import pytest

    secret = "https://discord.com/api/webhooks/123/example-secret"
    with pytest.raises(ValueError) as exc:
        rpc.dispatch(
            "notification",
            {"action": "save", "settings": {"discord": {"webhook_env": secret}}},
            "n",
            threading.Event(),
        )
    assert secret not in str(exc.value)


def test_web_settings_require_csrf_and_reads_never_send(service, tmp_path, monkeypatch):
    from vulnscan.storage.database import get_engine

    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").touch()
    client = TestClient(create_app(engine=get_engine(service.db_path)))
    result = client.get("/api/outbound/settings")
    assert result.status_code == 200
    assert result.json()["settings"]["mode"] == "manual"
    payload = {"mode": "automatic", "discord": {"enabled": True, "events": ["scan_failed"]}}
    assert client.post("/api/outbound/settings", json=payload).status_code == 403
    csrf = client.get("/api/health").cookies["vulnscan_csrf"]
    saved = client.post("/api/outbound/settings", json=payload, headers={"X-CSRF-Token": csrf})
    assert saved.status_code == 200
    assert saved.json()["settings"]["discord"]["events"] == ["scan_failed"]
    assert "example-secret" not in json.dumps(saved.json())


def test_web_validation_never_echoes_a_pasted_webhook(service, tmp_path, monkeypatch):
    from vulnscan.storage.database import get_engine

    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app(engine=get_engine(service.db_path)))
    csrf = client.get("/api/health").cookies["vulnscan_csrf"]
    secret = "https://discord.com/api/webhooks/123/example-secret"
    result = client.post("/api/outbound/settings", json=secret, headers={"X-CSRF-Token": csrf})
    assert secret not in result.text
    assert result.status_code == 400
