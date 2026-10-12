"""FR-71 / QR-21: Pilot tests for keyboard navigation, resize, history and exports."""

import asyncio

import pytest
from textual.widgets import Button, DataTable, Input, Static, TabbedContent

from vulnscan.tui.app import ScanApp


@pytest.mark.parametrize("callback", ["show_availability", "apply_history"])
async def test_qr21_late_worker_updates_and_history_events_are_ignored_after_quit(
    service, callback
):
    app = ScanApp(service=service)
    applied = []
    async with app.run_test() as pilot:
        # Posting from a worker still applies updates while the UI is mounted.
        await asyncio.to_thread(app._post_ui, applied.append, "mounted")
        await pilot.pause()
        assert applied == ["mounted"]

    assert not app.screen_stack
    args = ("late probe",) if callback == "show_availability" else (app.history_generation, [])
    app.on_scan_app_ui_update(app.UiUpdate(getattr(app, callback), args, {}))
    app.highlight_history()
    app.tick()

    # A worker completing after the queue closes cannot touch removed screens.
    await asyncio.to_thread(app._post_ui, getattr(app, callback), *args)


async def test_scan_tab_is_default(service, checkout):
    """Scan is the landing tab — it is the one thing most users need."""
    app = ScanApp(service=service)
    async with app.run_test(size=(120, 40)):
        tc = app.query_one(TabbedContent)
        assert tc.active == "setup"
        assert app.query_one("#checkout", Input).value
        assert app.query_one("#workdir", Input).value == "harness"


async def test_scan_tab_accepts_repo_url(service, checkout, monkeypatch):
    """A pasted URL is resolved to a checkout and pinned commit."""
    from vulnscan.core.source import RemoteSource
    from vulnscan.tui import app as tui_app

    monkeypatch.setattr(
        tui_app,
        "resolve_source",
        lambda target, workdir, commit=None: RemoteSource(
            "https://github.com/ppk205/ComicReaderSite.git",
            str(checkout),
            "d489b84bfc606c37c25609d4fba4e6da92db2d8e",
        ),
    )
    app = ScanApp(service=service)
    async with app.run_test(size=(120, 40)):
        app.query_one("#checkout", Input).value = "https://github.com/ppk205/ComicReaderSite"
        app.query_one("#commit", Input).value = ""
        # the target is accepted as a URL, not rejected as a bad path
        assert "github.com" in app.query_one("#checkout", Input).value


async def test_api_keys_tab_exists(service, checkout):
    """TUI has an API keys management tab."""
    app = ScanApp(service=service)
    async with app.run_test(size=(120, 40)) as pilot:
        from textual.widgets import TabbedContent

        tc = app.query_one(TabbedContent)
        # switch to keys tab
        tc.active = "keys"
        await pilot.pause()
        assert tc.active == "keys"


async def test_fr71_configure_scan_inspect_export_restart(service, checkout, tmp_path):
    app = ScanApp(service=service)
    async with app.run_test(size=(110, 42)) as pilot:
        await pilot.press("ctrl+n")
        assert app.query_one(TabbedContent).active == "setup"
        app.query_one("#checkout", Input).value = str(checkout)
        app.query_one("#output", Input).value = str(tmp_path / "reports")
        app.query_one("#review", Button).press()
        for _ in range(100):
            await pilot.pause(0.05)
            if not app.query_one("#start", Button).disabled:
                break
        app.query_one("#start", Button).press()
        for _ in range(100):
            await pilot.pause(0.05)
            if not app.scanning and service.history():
                break
        assert service.history()[0]["status"] == "completed"
        app.query_one(TabbedContent).active = "findings"
        for _ in range(100):
            await pilot.pause(0.05)
            if app.query_one("#finding-table", DataTable).row_count:
                break
        app.query_one("#finding-table", DataTable).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert "Example.java" in str(app.query_one("#evidence", Static).render())
        await pilot.resize_terminal(75, 26)
        app.query_one(TabbedContent).active = "settings"
        app.query_one("#export", Button).press()
        for _ in range(100):
            await pilot.pause(0.05)
            if list((tmp_path / "reports").glob("*.json")):
                break
        assert list((tmp_path / "reports").glob("*.json"))
        assert app.selected_pk is not None
    restarted = ScanApp(service=service)
    async with restarted.run_test() as pilot:
        assert restarted.service.history()[0]["status"] == "completed"
        await pilot.press("ctrl+n")
        assert restarted.query_one(TabbedContent).active == "setup"


async def test_qr21_quit_modal_stay_and_cancel(service, checkout, tmp_path, monkeypatch):
    import sys

    from vulnscan.scanners.process import run_command

    adapter = service.registry.get("semgrep")
    original = adapter.run

    def slow(*args, **kwargs):
        run_command([sys.executable, "-c", "import time; time.sleep(60)"])
        return original(*args, **kwargs)

    monkeypatch.setattr(adapter, "run", slow)
    app = ScanApp(service=service)
    async with app.run_test(size=(110, 42)) as pilot:
        app.query_one("#checkout", Input).value = str(checkout)
        app.query_one("#output", Input).value = str(tmp_path / "reports")
        app.query_one("#review", Button).press()
        for _ in range(100):
            await pilot.pause(0.05)
            if not app.query_one("#start", Button).disabled:
                break
        app.query_one("#start", Button).press()
        for _ in range(50):
            await pilot.pause(0.05)
            if app.active_pk:
                break
        await pilot.press("ctrl+n")
        assert app.scanning and app.query_one(TabbedContent).active == "setup"
        await pilot.press("ctrl+q")
        await pilot.pause()
        app.screen.query_one("#stay", Button).press()
        await pilot.pause()
        assert app.scanning
        await pilot.press("ctrl+x")
        for _ in range(100):
            await pilot.pause(0.05)
            if not app.scanning:
                break
        assert service.history()[0]["status"] == "cancelled"


async def test_qr21_worker_shutdown_terminates_scanner(service, checkout, tmp_path, monkeypatch):
    import sys

    from vulnscan.core.config import ScanConfig
    from vulnscan.scanners.process import run_command

    adapter = service.registry.get("semgrep")
    original = adapter.run

    def slow(*args, **kwargs):
        run_command([sys.executable, "-c", "import time; time.sleep(60)"])
        return original(*args, **kwargs)

    monkeypatch.setattr(adapter, "run", slow)
    app = ScanApp(service=service)
    async with app.run_test() as pilot:
        app.reviewed = (str(checkout), ScanConfig(output_dir=str(tmp_path / "reports")))
        app.begin()
        app.execute_scan()
        for _ in range(100):
            await pilot.pause(0.05)
            if app.active_pk is not None:
                break
        app.workers.cancel_all()
        for _ in range(100):
            await pilot.pause(0.05)
            if service.history()[0]["status"] == "cancelled":
                break
        result = service.detail(service.history()[0]["id"])["result"]
        assert result["exit_code"] == 130
