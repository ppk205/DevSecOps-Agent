"""FR-71 / QR-21: Pilot tests for keyboard navigation, resize, history and exports."""

from textual.widgets import Button, DataTable, Input, Static, TabbedContent

from vulnscan.tui.app import ScanApp


async def test_welcome_tab_is_default(service, checkout):
    """TUI opens on a friendly welcome/onboarding tab."""
    app = ScanApp(service=service)
    async with app.run_test(size=(120, 40)):
        from textual.widgets import Static, TabbedContent

        tc = app.query_one(TabbedContent)
        assert tc.active == "welcome"
        text = str(app.query_one("#welcome-text", Static).render())
        assert "DevSecOps" in text or "welcome" in text.lower()


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
        app.query_one("#finding-table", DataTable).focus()
        await pilot.press("enter")
        await pilot.pause()
        assert "Example.java" in str(app.query_one("#evidence", Static).render())
        await pilot.resize_terminal(75, 26)
        app.query_one(TabbedContent).active = "settings"
        app.query_one("#export", Button).press()
        await pilot.pause()
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
