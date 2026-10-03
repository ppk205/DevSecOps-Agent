"""FR-70/71, QR-16/21: real keyboard acceptance for the reviewed TUI workflow."""

import threading

import pytest
from textual.widgets import Button, DataTable, Input, Log, Static, TabbedContent

from tests.platform.test_scan_service import checkout, service, settings
from vulnscan.core.scan_service import ProgressEvent
from vulnscan.tui.app import DetailPane, ScanApp

__all__ = ["checkout", "service"]


async def wait_for(pilot, predicate):
    for _ in range(150):
        await pilot.pause(0.02)
        if predicate():
            return
    assert predicate(), "UI did not reach the expected state"


@pytest.mark.parametrize("size", [(80, 24), (75, 26)])
async def test_fr71_keyboard_review_scan_inspect_export_restart(
    service, checkout, tmp_path, monkeypatch, size
):
    monkeypatch.chdir(tmp_path)
    app = ScanApp(service=service)
    async with app.run_test(size=size) as pilot:
        await wait_for(pilot, lambda: not app.starting_service)
        await pilot.press("ctrl+n", *str(checkout))
        assert app.query_one("#checkout", Input).value == str(checkout)
        await pilot.press("ctrl+e")
        await wait_for(pilot, lambda: not app.query_one("#start", Button).disabled)
        assert "Commit:" in str(app.query_one("#effective", Static).render())
        await pilot.press("v", "pagedown")
        await pilot.pause()
        assert app.query_one("#review-pane", DetailPane).scroll_y > 0
        await pilot.press("ctrl+s")
        await wait_for(pilot, lambda: not app.scanning and bool(service.history()))
        assert service.history()[0]["status"] == "completed"
        await pilot.press("ctrl+4")
        await wait_for(pilot, lambda: app.query_one("#finding-table", DataTable).row_count > 0)
        await pilot.press("enter")
        await wait_for(pilot, lambda: app.query_one("#evidence-pane", DetailPane).display)
        assert "Example.java:1" in str(app.query_one("#evidence", Static).render())
        await pilot.press("v", "pagedown")
        await pilot.pause()
        assert app.query_one("#evidence-pane", DetailPane).scroll_y > 0
        await pilot.press("escape", "ctrl+5", "ctrl+o")
        await wait_for(pilot, lambda: bool(list((tmp_path / "artifacts").glob("*.json"))))
        assert "Export target:" in str(app.query_one("#export-target", Static).render())
        await pilot.press("ctrl+q")
    restarted = ScanApp(service=service)
    async with restarted.run_test(size=size) as pilot:
        await wait_for(pilot, lambda: restarted.query_one("#history", DataTable).row_count > 0)
        await pilot.press("ctrl+1", "enter", "ctrl+3")
        await wait_for(
            pilot,
            lambda: "Saved activity" in str(restarted.query_one("#run-status", Static).render()),
        )
        assert restarted.activity_pk == service.history()[0]["id"]


@pytest.mark.parametrize("action", ["ctrl+t", "ctrl+o"])
async def test_fr70_history_actions_use_highlighted_run(
    service, checkout, tmp_path, monkeypatch, action
):
    first = service.run(str(checkout), settings(tmp_path))
    second = service.run(str(checkout), settings(tmp_path))
    observed = []

    def retry(identifier, *args, **kwargs):
        observed.append(identifier)
        return second

    def export(identifier, *args, **kwargs):
        observed.append(identifier)
        return "fixture-export.json"

    monkeypatch.setattr(service, "retry", retry)
    monkeypatch.setattr(service, "export", export)
    app = ScanApp(service=service)
    async with app.run_test(size=(80, 24)) as pilot:
        await wait_for(pilot, lambda: app.query_one("#history", DataTable).row_count == 2)
        await pilot.press("ctrl+1", "down", "enter")
        assert app.selected_pk == first["id"]
        await pilot.press("ctrl+1", "up", action)
        await wait_for(pilot, lambda: bool(observed))
        assert observed == [second["id"]]


async def test_fr71_cursor_movement_preserves_pending_review(service, checkout, monkeypatch):
    from vulnscan.tui import app as module

    entered, release = threading.Event(), threading.Event()
    original = module.checkout_manifest

    def blocked(*args, **kwargs):
        entered.set()
        release.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "checkout_manifest", blocked)
    app = ScanApp(service=service)
    try:
        async with app.run_test() as pilot:
            await wait_for(pilot, lambda: not app.starting_service)
            await pilot.press("ctrl+n", *str(checkout), "ctrl+e")
            await wait_for(pilot, entered.is_set)
            await pilot.press("left")
            release.set()
            await wait_for(pilot, lambda: not app.query_one("#start", Button).disabled)
            assert app.reviewed is not None
    finally:
        release.set()


async def test_qr16_finished_errors_remain_visible(service):
    app = ScanApp(service=service)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.post_message(
            app.Finished(
                {
                    "run_id": "failed-run",
                    "status": "failed",
                    "exit_code": 2,
                    "errors": ["report export failed: disk full"],
                }
            )
        )
        await pilot.pause()
        lines = "\n".join(app.query_one("#progress-log", Log).lines)
        assert "disk full" in lines and "Next:" in lines


async def test_dr09_historical_activity_survives_other_run_events(service, checkout, tmp_path):
    first = service.run(str(checkout), settings(tmp_path))
    second = service.run(str(checkout), settings(tmp_path))
    app = ScanApp(service=service)
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: app.query_one("#history", DataTable).row_count == 2)
        await pilot.press("ctrl+1", "down", "enter", "ctrl+3")
        await wait_for(
            pilot, lambda: "Saved activity" in str(app.query_one("#run-status", Static).render())
        )
        app.active_pk = second["id"]
        app.on_scan_app_progress(
            app.Progress(
                ProgressEvent(
                    second["run_id"],
                    "other-run-stage",
                    "running",
                    "now",
                    "Run B only",
                    second["id"],
                )
            )
        )
        lines = "\n".join(app.query_one("#progress-log", Log).lines)
        assert "Run B only" not in lines
        assert app.activity_pk == first["id"]


async def test_qr21_actions_and_resize_are_accessible(service):
    app = ScanApp(service=service)
    async with app.run_test(size=(75, 26)) as pilot:
        await wait_for(pilot, lambda: not app.starting_service)
        await pilot.press("ctrl+n", "ctrl+5")
        assert app.query_one(TabbedContent).active == "settings"
        await pilot.press("ctrl+k")
        await pilot.pause()
        assert app.screen is not app.screen_stack[0]
        await pilot.press("escape")
        await pilot.resize_terminal(45, 12)
        await pilot.pause()
        assert app.query_one("#terminal-warning", Static).display
        assert not app.query_one(TabbedContent).display
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        assert app.query_one(TabbedContent).display


async def test_fr71_pinned_source_edits_invalidate_review(service):
    app = ScanApp(service=service)
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: not app.starting_service)
        before = app.capture_config()
        app.query_one("#commit", Input).value = "different-commit"
        await pilot.pause()
        assert before != app.capture_config()
        app.query_one("#workdir", Input).value = "different-cache"
        await pilot.pause()
        assert app.capture_config()[-1] == "different-cache"
        assert app.query_one("#start", Button).disabled


async def test_qr12_key_save_preserves_hidden_values(service, tmp_path, monkeypatch):
    import os

    from vulnscan.infra.envfile import EnvFile
    from vulnscan.tui import app as module

    target = EnvFile(tmp_path / "keys.env")
    monkeypatch.setattr(module, "EnvFile", lambda: target)
    monkeypatch.setenv("VULNSCAN_TUI_TEST_KEY", "parent-placeholder")
    del os.environ["VULNSCAN_TUI_TEST_KEY"]
    app = ScanApp(service=service)
    async with app.run_test() as pilot:
        await wait_for(pilot, lambda: not app.starting_service)
        app.query_one("#key-name", Input).value = "VULNSCAN_TUI_TEST_KEY"
        app.query_one("#key-value", Input).value = "fixture-hidden-value"
        app.query_one(TabbedContent).active = "keys"
        app.query_one("#key-save", Button).press()
        await wait_for(
            pilot, lambda: "Saved" in str(app.query_one("#keys-status", Static).render())
        )
        assert target.get("VULNSCAN_TUI_TEST_KEY") == "fixture-hidden-value"
        assert app.query_one("#key-value", Input).password
        assert not app.query_one("#key-value", Input).value
        assert "fixture-hidden-value" not in str(app.query_one("#keys-status", Static).render())
