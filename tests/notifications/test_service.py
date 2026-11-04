"""FR-75: selected delivery, pending choices and duplicate protection."""

from tests.platform.test_scan_service import checkout, service, settings
from vulnscan.notifications import service as notifications
from vulnscan.notifications.settings import NotificationSettings, save_settings
from vulnscan.notifications.transports import DeliveryResult

__all__ = ["checkout", "service"]


def configured(tmp_path, monkeypatch, mode="manual"):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").touch()
    cfg = NotificationSettings.model_validate(
        {
            "mode": mode,
            "telegram": {"enabled": True, "events": ["scan_completed", "gate_failed"]},
            "discord": {"enabled": True, "events": ["scan_completed", "report_ready"]},
        }
    )
    save_settings(cfg, base=tmp_path)
    monkeypatch.setattr(notifications.EnvFile, "load_into_environ", lambda self: [])
    return cfg


def result_for(service, checkout, tmp_path):
    return service.run(
        str(checkout),
        settings(tmp_path, mode="deterministic", laya=False, tools=["semgrep", "gitleaks"]),
    )


def test_manual_mode_creates_drafts_without_network_and_sends_only_selection(
    service, checkout, tmp_path, monkeypatch
):
    configured(tmp_path, monkeypatch)
    sent = []
    monkeypatch.setattr(
        notifications,
        "send_telegram",
        lambda message, **kwargs: (
            sent.append(("telegram", message)) or DeliveryResult("sent", "ack")
        ),
    )
    monkeypatch.setattr(
        notifications,
        "send_discord",
        lambda message, **kwargs: (
            sent.append(("discord", message)) or DeliveryResult("sent", "ack")
        ),
    )
    summary = result_for(service, checkout, tmp_path)
    offers = notifications.offer_run(service.db_path, summary["id"])
    assert sent == []
    assert len(offers["deliveries"]) == 2
    assert all(d["status"] == "pending" for d in offers["deliveries"])
    receipt = notifications.send_selected(
        service.db_path, summary["id"], ["scan_completed"], ["discord"]
    )
    assert receipt["deliveries"][0]["status"] == "sent"
    assert len(sent) == 1 and sent[0][0] == "discord"
    assert "Report formats available" not in sent[0][1]
    notifications.send_selected(service.db_path, summary["id"], ["scan_completed"], ["discord"])
    assert len(sent) == 1


def test_automatic_mode_sends_once_after_completion(service, checkout, tmp_path, monkeypatch):
    configured(tmp_path, monkeypatch, mode="automatic")
    calls = []
    monkeypatch.setattr(
        notifications,
        "send_telegram",
        lambda message, **kwargs: calls.append("telegram") or DeliveryResult("sent", "ack"),
    )
    monkeypatch.setattr(
        notifications,
        "send_discord",
        lambda message, **kwargs: calls.append("discord") or DeliveryResult("sent", "ack"),
    )
    summary = result_for(service, checkout, tmp_path)
    assert sorted(calls) == ["discord", "telegram"]
    offers = notifications.offer_run(service.db_path, summary["id"])
    assert sorted(calls) == ["discord", "telegram"]
    assert all(d["status"] == "sent" for d in offers["deliveries"])
    notifications.offer_run(service.db_path, summary["id"])
    assert len(calls) == 2


def test_delivery_failure_preserves_scan_and_finding_status(
    service, checkout, tmp_path, monkeypatch
):
    configured(tmp_path, monkeypatch, mode="automatic")
    monkeypatch.setattr(
        notifications,
        "send_telegram",
        lambda *args, **kwargs: DeliveryResult("failed", "HTTP 429", 429),
    )
    monkeypatch.setattr(
        notifications,
        "send_discord",
        lambda *args, **kwargs: DeliveryResult("unknown", "No acknowledgement"),
    )
    summary = result_for(service, checkout, tmp_path)
    before = service.detail(summary["id"])
    receipts = notifications.offer_run(service.db_path, summary["id"])
    after = service.detail(summary["id"])
    assert {d["status"] for d in receipts["deliveries"]} == {"failed", "unknown"}
    assert before["status"] == after["status"]
    assert [f["status"] for f in before["findings"]] == [f["status"] for f in after["findings"]]


def test_blank_or_unselected_events_do_not_send(service, checkout, tmp_path, monkeypatch):
    import pytest

    configured(tmp_path, monkeypatch)
    summary = result_for(service, checkout, tmp_path)
    notifications.offer_run(service.db_path, summary["id"])
    with pytest.raises(ValueError):
        notifications.send_selected(service.db_path, summary["id"], [], ["discord"])
    with pytest.raises(ValueError):
        notifications.send_selected(
            service.db_path, summary["id"], ["high_critical_findings"], ["discord"]
        )


def test_parallel_send_claims_only_once(service, checkout, tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    configured(tmp_path, monkeypatch)
    started, release = threading.Event(), threading.Event()
    calls = []

    def transport(message, **kwargs):
        calls.append(message)
        started.set()
        assert release.wait(5)
        return DeliveryResult("sent", "ack")

    monkeypatch.setattr(notifications, "send_discord", transport)
    summary = result_for(service, checkout, tmp_path)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(
            notifications.send_selected,
            service.db_path,
            summary["id"],
            ["scan_completed"],
            ["discord"],
        )
        assert started.wait(5)
        second = pool.submit(
            notifications.send_selected,
            service.db_path,
            summary["id"],
            ["scan_completed"],
            ["discord"],
        )
        assert second.result()["deliveries"][0]["status"] == "sending"
        release.set()
        assert first.result()["deliveries"][0]["status"] == "sent"
    assert len(calls) == 1


def test_unknown_delivery_requires_explicit_retry(service, checkout, tmp_path, monkeypatch):
    configured(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(
        notifications,
        "send_discord",
        lambda *args, **kwargs: calls.append(1) or DeliveryResult("unknown", "No acknowledgement"),
    )
    summary = result_for(service, checkout, tmp_path)
    args = (service.db_path, summary["id"], ["scan_completed"], ["discord"])
    notifications.send_selected(*args)
    notifications.send_selected(*args)
    assert len(calls) == 1
    notifications.send_selected(*args, retry=True)
    assert len(calls) == 2


def test_disabled_notifications_do_not_load_credentials(service, checkout, tmp_path, monkeypatch):
    def forbidden(*args):
        raise AssertionError("Disabled notification stage must not load credentials")

    monkeypatch.setattr(notifications.EnvFile, "load_into_environ", forbidden)
    summary = result_for(service, checkout, tmp_path)
    assert summary["notifications"]["status"] == "disabled"
