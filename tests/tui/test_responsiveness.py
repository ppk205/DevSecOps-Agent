"""QR-21: real UI navigation while a service call is deliberately blocked."""

import asyncio
import threading

from textual.widgets import Input, TabbedContent

from vulnscan.tui.app import ScanApp


async def test_navigation_remains_responsive_during_history_read(service, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = service.history

    def blocked_history():
        entered.set()
        release.wait(timeout=5)
        return original()

    monkeypatch.setattr(service, "history", blocked_history)
    app = ScanApp(service=service)
    try:
        async with app.run_test(size=(75, 26)) as pilot:
            for _ in range(100):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            assert entered.is_set()
            await asyncio.wait_for(pilot.press("ctrl+n"), timeout=1)
            assert app.query_one(TabbedContent).active == "setup"
            release.set()
            await pilot.pause()
    finally:
        release.set()


async def test_invalid_numeric_edit_does_not_crash_review_callback(service):
    app = ScanApp(service=service)
    async with app.run_test() as pilot:
        await pilot.pause()
        signature = app.capture_config()
        app.query_one("#timeout", Input).value = ""
        # A pending review may arrive while a number field is temporarily empty.
        app.review_failed(signature, "old review error")
        await pilot.press("ctrl+n")
        assert app.query_one(TabbedContent).active == "setup"
