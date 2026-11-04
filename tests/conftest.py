"""Keep operator notification rules and live destinations out of offline tests."""

import pytest


@pytest.fixture(autouse=True)
def isolated_notification_settings(tmp_path, monkeypatch):
    from vulnscan.notifications import settings, transports

    monkeypatch.setattr(
        settings,
        "settings_path",
        lambda base=None: (base or tmp_path) / ".devsec-notifications.json",
    )

    def no_live_notification(*args, **kwargs):
        raise AssertionError(
            "Live notification HTTP is disabled in tests; use a synthetic transport"
        )

    monkeypatch.setattr(transports, "_post_json", no_live_notification)
