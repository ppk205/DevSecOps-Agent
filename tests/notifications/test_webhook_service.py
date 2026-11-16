"""FR-75: webhook offers and uncertain deliveries retain their identity."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.notifications.test_service import checkout, result_for, service
from vulnscan.notifications import service as notifications
from vulnscan.notifications.settings import save_settings
from vulnscan.notifications.transports import DeliveryResult

__all__ = ["checkout", "service"]


def configure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").touch()
    monkeypatch.setenv("DEVSEC_WEBHOOK_URL", "https://hooks.example.com/a")
    monkeypatch.setenv("DEVSEC_WEBHOOK_SIGNING_SECRET", "k" * 32)
    monkeypatch.setattr(notifications.EnvFile, "load_into_environ", lambda self: [])
    save_settings(
        {
            "webhook": {
                "enabled": True,
                "events": ["scan_completed"],
                "allowed_hosts": ["hooks.example.com"],
            }
        },
        base=tmp_path,
    )


def test_offer_send_and_explicit_retry_keep_body_and_id(service, checkout, tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(
        notifications,
        "send_webhook",
        lambda body, **kw: (
            calls.append((body, kw["delivery_id"])) or DeliveryResult("unknown", "uncertain")
        ),
    )
    run = result_for(service, checkout, tmp_path)
    offers = notifications.offer_run(service.db_path, run["id"])
    receipt = offers["deliveries"][0]
    assert receipt["channel"] == "webhook" and receipt["delivery_id"]
    assert calls == []
    args = (service.db_path, run["id"], ["scan_completed"], ["webhook"])
    assert notifications.send_selected(*args)["deliveries"][0]["status"] == "unknown"
    notifications.send_selected(*args)
    assert len(calls) == 1
    notifications.send_selected(*args, retry=True)
    assert len(calls) == 2 and calls[0] == calls[1]


def test_destination_change_blocks_send(service, checkout, tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    monkeypatch.setattr(notifications, "send_webhook", lambda *a, **k: pytest.fail("sent"))
    run = result_for(service, checkout, tmp_path)
    notifications.offer_run(service.db_path, run["id"])
    monkeypatch.setenv("DEVSEC_WEBHOOK_URL", "https://hooks.example.com/b")
    with pytest.raises(ValueError, match="destination"):
        notifications.send_selected(service.db_path, run["id"], ["scan_completed"], ["webhook"])


def test_concurrent_webhook_sends_claim_once(service, checkout, tmp_path, monkeypatch):
    configure(tmp_path, monkeypatch)
    started, release = threading.Event(), threading.Event()
    calls = []

    def transport(body, **kwargs):
        calls.append(body)
        started.set()
        assert release.wait(10)
        return DeliveryResult("sent", "acknowledged")

    monkeypatch.setattr(notifications, "send_webhook", transport)
    run = result_for(service, checkout, tmp_path)
    args = (service.db_path, run["id"], ["scan_completed"], ["webhook"])
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(notifications.send_selected, *args)
        assert started.wait(10)
        second = pool.submit(notifications.send_selected, *args)
        assert second.result()["deliveries"][0]["status"] == "sending"
        release.set()
        assert first.result()["deliveries"][0]["status"] == "sent"
    notifications.offer_run(service.db_path, run["id"])
    assert len(calls) == 1
