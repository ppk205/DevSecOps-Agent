"""FR-75: the Python fallback also keeps outbound sends explicit."""

import pytest
from textual.app import App

from vulnscan.tui.notifications import NotificationsDialog


@pytest.mark.asyncio
async def test_manual_dialog_opens_unselected_and_escape_sends_nothing(monkeypatch):
    import vulnscan.tui.notifications as ui

    calls = []
    monkeypatch.setattr(ui, "handle", lambda *args: calls.append(args))
    receipt = {
        "run_id": "example",
        "deliveries": [
            {
                "channel": "discord",
                "status": "pending",
                "events": [
                    {
                        "kind": "scan_completed",
                        "label": "Scan completed",
                        "message": "Scan example completed.",
                    }
                ],
            }
        ],
    }
    app = App()
    async with app.run_test(size=(80, 24)) as pilot:
        dialog = NotificationsDialog("unused.db", receipt)
        await app.push_screen(dialog)
        await pilot.pause()
        assert dialog.query_one("#send-channels").selected == []
        assert dialog.query_one("#send-events").selected == []
        await pilot.press("escape")
        assert app.screen is not dialog
    assert calls == []
