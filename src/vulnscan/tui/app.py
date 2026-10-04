"""Keyboard-accessible persistent scan workspace (FR-71, QR-21)."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from datetime import datetime
from threading import Event
from typing import Any, ClassVar
from zoneinfo import ZoneInfo

from textual import on, work
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.events import Resize
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.timer import Timer
from textual.widgets import (
    Button,
    Collapsible,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    Select,
    Static,
    TabbedContent,
    TabPane,
)
from textual.worker import get_current_worker

from vulnscan.contracts import ExportFormat
from vulnscan.core.config import ScanConfig, resolve_config
from vulnscan.core.scan_service import ProgressEvent, ScanService, checkout_manifest
from vulnscan.core.source import LocalSource, RemoteSource, resolve_source
from vulnscan.infra.envfile import EnvFile
from vulnscan.version import APP_VERSION

from .presentation import (
    complete_path,
    finding_summary,
    recovery_advice,
    result_lines,
    review_summary,
)

ReviewSignature = tuple[str, str, str | None, dict[str, Any], str, str]


class DetailPane(VerticalScroll):
    """An explicitly focused review/evidence reader with visible keyboard hints."""

    BINDINGS: ClassVar = [
        Binding("pageup", "page_up", "Scroll up"),
        Binding("pagedown", "page_down", "Scroll down"),
        Binding("v", "app.toggle_details", "Raw details"),
        Binding("escape", "app.leave_panel", "Back"),
    ]


class QuitScan(ModalScreen[bool]):
    BINDINGS: ClassVar = [
        ("escape,n", "stay", "Stay"),
        ("y", "cancel_quit", "Cancel and quit"),
    ]

    def action_stay(self) -> None:
        self.dismiss(False)

    def action_cancel_quit(self) -> None:
        self.dismiss(True)

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label(
                "A scan is active. Cancel it and preserve partial evidence before quitting?"
            )
            yield Button("Stay", id="stay", variant="primary")
            yield Button("Cancel and quit", id="cancel-quit", variant="error")

    @on(Button.Pressed)
    def choose(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "cancel-quit")


class ScanApp(App[None]):
    TITLE = f"DevSecOps Agent {APP_VERSION}"
    BINDINGS: ClassVar = [
        Binding("ctrl+k", "command_palette", "Actions", priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+n", "setup", "New scan", priority=True),
        Binding("ctrl+r", "history", "History", show=False, priority=True),
        Binding("ctrl+e", "review", "Review", show=False, priority=True),
        Binding("ctrl+s", "start", "Start", show=False, priority=True),
        Binding("ctrl+t", "retry", "Retry", show=False, priority=True),
        Binding("ctrl+o", "export", "Export", show=False, priority=True),
        Binding("ctrl+x", "cancel", "Cancel", show=False, priority=True),
        Binding("ctrl+1", "view('overview')", "History", show=False, priority=True),
        Binding("ctrl+2", "view('setup')", "Workspace", show=False, priority=True),
        Binding("ctrl+3", "view('progress')", "Activity", show=False, priority=True),
        Binding("ctrl+4", "view('findings')", "Findings", show=False, priority=True),
        Binding("ctrl+5", "view('settings')", "Reports", show=False, priority=True),
        Binding("ctrl+space", "complete_checkout", "Complete path", show=False, priority=True),
    ]
    CSS = """
    TabPane { padding: 1; }
    Input, Select, Button { margin-bottom: 1; }
    DataTable { height: 1fr; min-height: 6; }
    #evidence { height: auto; min-height: 5; }
    #effective { height: auto; }
    #review-pane { height: 10; display: none; border: solid $accent; }
    #evidence-pane { height: 1fr; display: none; border: solid $accent; }
    #detail-hint { display: none; height: auto; }
    #scan-actions { height: 3; }
    #scan-actions Button { margin-right: 1; }
    #availability { height: auto; max-height: 4; }
    #run-target, #export-target { height: auto; }
    #progress-log { height: 1fr; }
    #paging { height: 3; }
    #paging Button { margin-right: 1; }
    QuitScan { align: center middle; background: $background 80%; }
    #terminal-warning { display: none; height: auto; padding: 1; }
    QuitScan VerticalScroll { width: 95%; max-width: 64; height: auto; max-height: 95%; border: thick $accent; padding: 1; }
    """

    class Progress(Message):
        def __init__(self, event: ProgressEvent) -> None:
            self.event = event
            super().__init__()

    class Finished(Message):
        def __init__(self, result: dict[str, Any]) -> None:
            self.result = result
            super().__init__()

    class UiUpdate(Message):
        def __init__(
            self, callback: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
        ) -> None:
            super().__init__()
            self.callback, self.args, self.kwargs = callback, args, kwargs

    def __init__(self, db_path: str = "vulnscan.db", service: ScanService | None = None) -> None:
        super().__init__()
        self._service = service
        self.db_path = db_path
        self.active_pk: int | None = None
        self.selected_pk: int | None = None
        self.scanning = False
        self.cancel_pending = False
        self.edited: set[str] = set()
        self.ready = False
        self.quit_after_scan = False
        self.started = 0.0
        self.items: list[dict[str, Any]] = []
        self.source: LocalSource | RemoteSource | None = None
        self.reviewed: tuple[str, ScanConfig] | None = None
        self.review_signature: ReviewSignature | None = None
        self.cancel_signal = Event()
        self.page_offset = 0
        self.page_total = 0
        self.findings_generation = 0
        self.evidence_generation = 0
        self.history_generation = 0
        self.displayed_revision = -1
        self.findings_dirty = False
        self.filter_timer: Timer | None = None
        self.starting_service = True
        self.pending_review: ReviewSignature | None = None
        self.service_ready = Event()
        self.review_text = ""
        self.review_raw = ""
        self.evidence_text = ""
        self.evidence_raw = ""
        self.raw_review = False
        self.raw_evidence = False
        self.viewed_run_id = ""
        self.activity_pk: int | None = None
        self.activity_generation = 0
        self.active_log: list[str] = []
        self.active_result: dict[str, Any] | None = None
        self.follow_active = True
        self.requested_pane: str | None = None
        self.scan_generation = 0
        self.activity_polling = False
        self.partial_findings: int | None = None
        self.current_stage = "Preparing checkout"
        self.active_run_id = ""

    @property
    def service(self) -> ScanService:
        if self._service is None:
            raise RuntimeError("Scan workspace is still loading")
        return self._service

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "Use at least 60 columns and 18 rows. Resize to continue.",
            id="terminal-warning",
            markup=False,
        )
        with TabbedContent(initial="setup"):
            with TabPane("History", id="overview"):
                yield Static("Checking scanner availability...", id="availability", markup=False)
                yield DataTable(id="history", cursor_type="row")
                yield Static("No run highlighted", id="run-target", markup=False)
                yield Button("Retry highlighted run", id="retry", disabled=True)
            with TabPane("Workspace", id="setup"), VerticalScroll():
                yield Label(
                    "Repository URL or local checkout (Ctrl+Space completes local directories)"
                )
                yield Input("https://github.com/ppk205/ComicReaderSite", id="checkout")
                yield Select(
                    [
                        ("Fast: Semgrep + Gitleaks", "fast"),
                        ("Full: isolated Maven + all scanners", "full"),
                    ],
                    value="fast",
                    allow_blank=False,
                    id="profile",
                )
                with Collapsible(title="Advanced scan options", collapsed=True, id="advanced"):
                    yield Label("Pinned commit (blank uses the resolved checkout HEAD)")
                    yield Input(placeholder="optional commit SHA", id="commit")
                    yield Label("Clone cache folder")
                    yield Input("harness", id="workdir")
                    yield Label("Optional versioned configuration file")
                    yield Input(placeholder="config/scan.json", id="config-path")
                    yield Label("Wall-clock limit (seconds)")
                    yield Input("600", id="timeout")
                    yield Label("Maximum source files")
                    yield Input("100000", id="max-files")
                    yield Label("Artifact directory")
                    yield Input("artifacts", id="output")
                    yield Label("Display timezone")
                    yield Input("Asia/Saigon", id="timezone")
                    yield Select(
                        [
                            (s.title(), s)
                            for s in ["critical", "high", "medium", "low", "info", "none"]
                        ],
                        value="high",
                        allow_blank=False,
                        id="threshold",
                    )
                    yield Select(
                        [
                            ("Clean checkout required", "clean"),
                            ("Allow dirty local contents and record hashes", "dirty"),
                        ],
                        value="clean",
                        allow_blank=False,
                        id="dirty",
                    )
                    yield Select(
                        [
                            ("Laya disabled (deterministic)", "off"),
                            ("Laya advisory enabled (local model required)", "on"),
                        ],
                        value="off",
                        allow_blank=False,
                        id="laya",
                    )
                    yield Label("Optional Laya advisory configuration file")
                    yield Input(placeholder="config/laya.json", id="laya-config-path")
                with Horizontal(id="scan-actions"):
                    yield Button("Review (Ctrl+E)", id="review")
                    yield Button("Start (Ctrl+S)", id="start", variant="primary", disabled=True)
                with DetailPane(id="review-pane"):
                    yield Static("Review settings before starting.", id="effective", markup=False)
            with TabPane("Activity", id="progress"):
                yield Static(
                    "Choose a run in History, or start a new scan.", id="run-status", markup=False
                )
                yield Log(id="progress-log")
                yield Button("Cancel active scan", id="cancel", variant="error", disabled=True)
            with TabPane("Findings", id="findings"):
                yield Input(
                    placeholder="Search or severity:high cwe:89 scanner:semgrep", id="filter"
                )
                yield DataTable(id="finding-table", cursor_type="row")
                with Horizontal(id="paging"):
                    yield Button("Previous", id="previous", disabled=True)
                    yield Button("Next", id="next", disabled=True)
                    yield Static("0 findings", id="page-status", markup=False)
                yield Static(
                    "PgUp/PgDown: scroll | V: raw details | Esc: findings",
                    id="detail-hint",
                    markup=False,
                )
                with DetailPane(id="evidence-pane"):
                    yield Static("Select a finding and press Enter.", id="evidence", markup=False)
            with TabPane("Reports", id="settings"), VerticalScroll():
                yield Static(
                    "Open a run from History before exporting.", id="export-target", markup=False
                )
                yield Select(
                    [(f.value.upper(), f.value) for f in ExportFormat],
                    value="json",
                    allow_blank=False,
                    id="format",
                )
                yield Button("Export named run (Ctrl+O)", id="export", disabled=True)
                yield Static("No export yet", id="export-path", markup=False)
            with TabPane("API Keys", id="keys"), VerticalScroll():
                yield Label("Variable name (e.g. LAYA_API_KEY)")
                yield Input(placeholder="VARIABLE_NAME", id="key-name")
                yield Label("Value (hidden; cleared after saving)")
                yield Input(placeholder="paste secret, then Save", password=True, id="key-value")
                yield Button("Save to project .env", id="key-save")
                yield Static("", id="keys-status", markup=False)
                yield Label("Stored key names (values never shown):")
                yield Static("No keys stored", id="keys-list", markup=False)
        yield Footer()

    def on_resize(self, event: Resize) -> None:
        if not self.screen_stack:
            return
        screen = self.screen_stack[0]
        if not screen.query("#terminal-warning"):
            return
        small = event.size.width < 60 or event.size.height < 18
        screen.query_one("#terminal-warning", Static).display = small
        screen.query_one(TabbedContent).display = not small

    def on_mount(self) -> None:
        self.screen_stack[0].query_one("#history", DataTable).add_columns(
            "ID", "Run", "Status", "Attempt", "Started"
        )
        self.screen_stack[0].query_one("#finding-table", DataTable).add_columns(
            "Severity", "CWE", "Status", "Scanner", "Title"
        )
        self.initialize()
        self.set_interval(0.5, self.tick)
        self.call_after_refresh(self.enable_edits)

    def _post_ui(self, callback: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        """Deliver worker updates through the UI queue while its screen exists."""
        self.post_message(self.UiUpdate(callback, args, kwargs))

    def on_scan_app_ui_update(self, message: UiUpdate) -> None:
        if self.is_running and self.screen_stack:
            message.callback(*message.args, **message.kwargs)

    @work(thread=True, group="initialize")
    def initialize(self) -> None:
        try:
            EnvFile().load_into_environ()
            if self._service is None:
                self._service = ScanService(self.db_path)
            self.service.recover()
            self.service_ready.set()
            self._post_ui(self.initialized)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self._post_ui(self.notify, str(exc), severity="error")

    def initialized(self) -> None:
        self.starting_service = False
        self.action_refresh()
        self.probe()
        self.refresh_keys_list()
        if self.requested_pane is not None:
            self.call_after_refresh(self.action_view, self.requested_pane)
        if self.pending_review is not None:
            self.review_checkout(self.pending_review)
            self.pending_review = None

    @work(thread=True)
    def probe(self) -> None:
        labels = []
        for adapter in self.service.registry.adapters.values():
            cap = adapter.capabilities()
            labels.append(
                f"{cap.tool.value}: "
                + (
                    f"available {cap.version or ''}"
                    if cap.available
                    else f"unavailable — install {cap.binary or cap.tool.value} on PATH"
                )
            )
        self._post_ui(self.show_availability, "\n".join(labels))

    def show_availability(self, value: str) -> None:
        self.screen_stack[0].query_one("#availability", Static).update(value)

    def action_setup(self) -> None:
        self.action_view("setup")

    def action_view(self, pane: str) -> None:
        target = self.action_target()
        self.requested_pane = pane
        self.screen_stack[0].query_one(TabbedContent).active = pane
        if pane == "overview":
            self.screen_stack[0].query_one("#history", DataTable).focus()
        elif pane == "setup":
            self.screen_stack[0].query_one("#checkout", Input).focus()
        elif pane == "settings":
            self.update_targets()
            self.screen_stack[0].query_one("#format", Select).focus()
        elif pane == "progress":
            if target is not None:
                self.show_activity(target)
            self.screen_stack[0].query_one("#progress-log", Log).focus()
        elif pane == "findings":
            self.action_leave_panel()

    def action_history(self) -> None:
        self.action_view("overview")
        self.screen_stack[0].query_one("#history", DataTable).focus()
        self.action_refresh()

    def action_target(self) -> int | None:
        screen = self.screen_stack[0]
        if screen.query_one(TabbedContent).active == "overview":
            table = screen.query_one("#history", DataTable)
            return int(table.get_row_at(table.cursor_row)[0]) if table.row_count else None
        return self.selected_pk

    def update_targets(self) -> None:
        if not self.is_running or not self.screen_stack:
            return
        screen = self.screen_stack[0]
        table = screen.query_one("#history", DataTable)
        row = table.get_row_at(table.cursor_row) if table.row_count else None
        screen.query_one("#run-target", Static).update(
            f"Highlighted run: {row[1]}" if row else "No run highlighted"
        )
        screen.query_one("#retry", Button).disabled = (
            row is None or self.scanning or row[2] in {"running", "queued"}
        )
        screen.query_one("#export", Button).disabled = self.selected_pk is None
        screen.query_one("#export-target", Static).update(
            f"Export target: {self.viewed_run_id or self.selected_pk}\n"
            f"Artifact directory: {screen.query_one('#output', Input).value}"
            if self.selected_pk is not None
            else "Open a run from History before exporting."
        )

    @on(DataTable.RowHighlighted, "#history")
    def highlight_history(self) -> None:
        self.update_targets()

    def get_system_commands(self, screen: Screen[Any]) -> Iterable[SystemCommand]:
        yield SystemCommand("New scan", "Configure the checkout in Workspace", self.action_setup)
        yield SystemCommand("History", "Choose a saved run", self.action_history)
        yield SystemCommand("Review checkout", "Inspect effective settings", self.action_review)
        yield SystemCommand("Start reviewed scan", "Run the reviewed settings", self.action_start)
        yield SystemCommand("Retry run", "Retry the highlighted or opened run", self.action_retry)
        yield SystemCommand(
            "Export run", "Export the highlighted or opened run", self.action_export
        )
        yield SystemCommand("Cancel scan", "Retain partial evidence", self.action_cancel)
        yield SystemCommand(
            "API Keys", "Manage hidden project credentials", lambda: self.action_view("keys")
        )
        for title, pane in [
            ("Activity", "progress"),
            ("Findings", "findings"),
            ("Reports", "settings"),
        ]:
            yield SystemCommand(title, f"Open {title}", lambda pane=pane: self.action_view(pane))
        yield SystemCommand("Quit", "Confirm cancellation if scanning", self.action_quit)

    def action_review(self) -> None:
        self.action_view("setup")
        self.screen_stack[0].query_one("#review", Button).press()

    def action_start(self) -> None:
        if self.reviewed is None or self.review_signature != self.capture_config():
            self.notify("Review the current settings with Ctrl+E first", severity="warning")
            return
        self.screen_stack[0].query_one("#start", Button).press()

    def action_retry(self) -> None:
        target = self.action_target()
        if target is not None and not self.scanning:
            table = self.screen_stack[0].query_one("#history", DataTable)
            if self.screen_stack[0].query_one(
                TabbedContent
            ).active == "overview" and table.get_row_at(table.cursor_row)[2] in {
                "running",
                "queued",
            }:
                self.notify("This run is active. Open its Activity instead.", severity="warning")
                return
            self.begin()
            self.execute_scan(target)

    def action_export(self) -> None:
        target = self.action_target()
        if target is None:
            self.notify("Choose a run from History before exporting", severity="warning")
            return
        screen = self.screen_stack[0]
        self.export_run(
            target,
            ExportFormat(screen.query_one("#format", Select).value),
            screen.query_one("#output", Input).value,
        )

    @work(thread=True, exclusive=True, group="keys-list")
    def refresh_keys_list(self) -> None:
        names = EnvFile().names()
        self._post_ui(self.apply_keys_list, names)

    def apply_keys_list(self, names: list[str]) -> None:
        self.screen_stack[0].query_one("#keys-list", Static).update(
            "\n".join(f"{name} (stored, value hidden)" for name in names) or "No keys stored"
        )

    @work(thread=True, exclusive=True, group="key-save")
    def save_key(self, name: str, value: str) -> None:
        try:
            path = EnvFile().set(name, value)
            EnvFile().load_into_environ()
            message = f"Saved {name.strip().upper()} to project .env ({path})"
            self._post_ui(self.key_saved, name, value, message)
        except (ValueError, OSError) as exc:
            self._post_ui(self.key_failed, str(exc))

    def key_failed(self, message: str) -> None:
        self.screen_stack[0].query_one("#keys-status", Static).update(message)

    def key_saved(self, name: str, value: str, message: str) -> None:
        screen = self.screen_stack[0]
        if (
            screen.query_one("#key-name", Input).value == name
            and screen.query_one("#key-value", Input).value == value
        ):
            screen.query_one("#key-name", Input).value = ""
            screen.query_one("#key-value", Input).value = ""
        screen.query_one("#keys-status", Static).update(message)
        self.refresh_keys_list()

    def action_leave_panel(self) -> None:
        screen = self.screen_stack[0]
        if screen.query_one(TabbedContent).active == "setup":
            screen.query_one("#review", Button).focus()
        else:
            screen.query_one("#evidence-pane", DetailPane).display = False
            screen.query_one("#detail-hint", Static).display = False
            screen.query_one("#finding-table", DataTable).display = True
            screen.query_one("#filter", Input).display = True
            screen.query_one("#paging", Horizontal).display = True
            screen.query_one("#finding-table", DataTable).focus()

    def action_toggle_details(self) -> None:
        screen = self.screen_stack[0]
        if screen.query_one(TabbedContent).active == "setup":
            self.raw_review = not self.raw_review
            screen.query_one("#effective", Static).update(
                self.review_raw if self.raw_review else self.review_text
            )
        else:
            self.raw_evidence = not self.raw_evidence
            screen.query_one("#evidence", Static).update(
                self.evidence_raw if self.raw_evidence else self.evidence_text
            )

    def action_complete_checkout(self) -> None:
        screen = self.screen_stack[0]
        if self.focused is screen.query_one("#checkout", Input):
            self.complete_checkout(screen.query_one("#checkout", Input).value)

    @work(thread=True, exclusive=True, group="path-completion")
    def complete_checkout(self, value: str) -> None:
        completed, message = complete_path(value)
        self._post_ui(self.apply_completion, value, completed, message)

    def apply_completion(self, previous: str, completed: str, message: str) -> None:
        widget = self.screen_stack[0].query_one("#checkout", Input)
        if widget.value == previous:
            widget.value = completed
            self.notify(message)

    def action_refresh(self) -> None:
        if self.starting_service:
            return
        self.history_generation += 1
        self.fetch_history(self.history_generation)

    @work(thread=True, exclusive=True, group="history")
    def fetch_history(self, generation: int) -> None:
        try:
            rows = self.service.history()
            self._post_ui(self.apply_history, generation, rows)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self._post_ui(self.notify, str(exc), severity="error")

    def apply_history(self, generation: int, rows: list[dict[str, Any]]) -> None:
        if generation != self.history_generation:
            return
        table = self.screen_stack[0].query_one("#history", DataTable)
        selected = table.get_row_at(table.cursor_row)[0] if table.row_count else None
        scroll = table.scroll_offset
        table.clear()
        try:
            zone = ZoneInfo(self.screen_stack[0].query_one("#timezone", Input).value)
        except (ValueError, KeyError):
            zone = ZoneInfo("Asia/Saigon")
        for index, row in enumerate(rows):
            stamp = (
                datetime.fromisoformat(row["created_at"])
                .astimezone(zone)
                .strftime("%Y-%m-%d %H:%M %z")
            )
            table.add_row(
                str(row["id"]),
                row["run_id"],
                row["status"],
                str(row["attempt"]),
                stamp,
                key=str(row["id"]),
            )
            if str(row["id"]) == selected:
                table.move_cursor(row=index)
        table.scroll_to(x=scroll.x, y=scroll.y, animate=False)
        self.update_targets()

    def tick(self) -> None:
        if not self.is_running or not self.screen_stack:
            return
        if self.scanning and self.activity_pk == self.active_pk:
            count = str(self.partial_findings) if self.partial_findings is not None else "pending"
            self.screen_stack[0].query_one("#run-status", Static).update(
                f"Active · {self.active_run_id or 'starting'} · {self.current_stage}\n"
                f"{time.monotonic() - self.started:.0f}s · retained findings: {count} · partial evidence saved"
            )
            if self.active_pk is not None and not self.activity_polling:
                self.activity_polling = True
                self.fetch_active_count(self.active_pk, self.scan_generation)
        if (
            self.scanning
            and self.active_pk is not None
            and self.selected_pk == self.active_pk
            and self.findings_dirty
            and self.screen_stack[0].query_one(TabbedContent).active == "findings"
        ):
            self.load_findings(self.active_pk)

    @work(thread=True, exclusive=True, group="activity-count")
    def fetch_active_count(self, pk: int, generation: int) -> None:
        try:
            count = int(self.service.activity(pk)["result"]["findings"])
        except Exception:  # noqa: BLE001 - optional read-only progress projection
            count = None
        self._post_ui(self.apply_active_count, pk, generation, count)

    def apply_active_count(self, pk: int, generation: int, count: int | None) -> None:
        if pk == self.active_pk and generation == self.scan_generation:
            self.activity_polling = False
            self.partial_findings = count

    def load_findings(self, pk: int) -> None:
        self.findings_generation += 1
        self.findings_dirty = False
        self.fetch_findings(
            pk,
            self.screen_stack[0].query_one("#filter", Input).value,
            self.page_offset,
            self.findings_generation,
        )

    @work(thread=True, exclusive=True, group="findings")
    def fetch_findings(self, pk: int, query: str, offset: int, generation: int) -> None:
        try:
            page = self.service.finding_page(pk, query, offset)
            self._post_ui(self.apply_findings, pk, generation, page)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self._post_ui(self.notify, str(exc), severity="error")

    def apply_findings(self, pk: int, generation: int, page: dict[str, Any]) -> None:
        if generation != self.findings_generation or pk != self.selected_pk:
            return
        if page["offset"] >= page["total"] and page["offset"] > 0:
            self.page_offset = max(0, ((page["total"] - 1) // 200) * 200)
            self.load_findings(pk)
            return
        self.displayed_revision = page["revision"]
        self.page_total = page["total"]
        if self.items != page["items"]:
            self.items = page["items"]
            self.render_findings()
        screen = self.screen_stack[0]
        screen.query_one("#previous", Button).disabled = self.page_offset == 0
        screen.query_one("#next", Button).disabled = self.page_offset + 200 >= self.page_total
        screen.query_one("#page-status", Static).update(
            f"{min(self.page_offset + 1, self.page_total)}–"
            f"{min(self.page_offset + 200, self.page_total)} of {self.page_total} findings"
        )

    @on(Input.Changed, "#filter")
    def filter_findings(self) -> None:
        if self.filter_timer:
            self.filter_timer.stop()
        self.findings_generation += 1
        self.page_offset = 0
        self.filter_timer = self.set_timer(0.15, self.refresh_findings)

    def refresh_findings(self) -> None:
        if self.selected_pk is not None:
            self.load_findings(self.selected_pk)

    @on(TabbedContent.TabActivated)
    def tab_activated(self, event: TabbedContent.TabActivated) -> None:
        if event.pane.id == "findings" and self.findings_dirty:
            self.refresh_findings()

    def render_findings(self) -> None:
        table = self.screen_stack[0].query_one("#finding-table", DataTable)
        selected = table.get_row_at(table.cursor_row) if table.row_count else None
        selected_key = (
            str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
            if selected
            else None
        )
        old_row, scroll = table.cursor_row, table.scroll_offset
        table.clear()
        restore = min(old_row, max(0, len(self.items) - 1))
        for index, item in enumerate(self.items):
            table.add_row(
                item["severity"],
                item["cwe_category"],
                item["status"],
                item["scanner"],
                item["title"],
                key=item["finding_id"],
            )
            if item["finding_id"] == selected_key:
                restore = index
        table.move_cursor(row=restore)
        table.scroll_to(x=scroll.x, y=scroll.y, animate=False)

    @on(DataTable.RowSelected)
    def select_row(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "history":
            self.selected_pk = int(str(event.row_key.value))
            self.follow_active = False
            self.viewed_run_id = str(event.data_table.get_row_at(event.cursor_row)[1])
            self.page_offset = 0
            self.items = []
            self.evidence_generation += 1
            self.screen_stack[0].query_one("#evidence", Static).update(
                "Select a finding to inspect evidence."
            )
            self.load_findings(self.selected_pk)
            self.show_activity(self.selected_pk)
            self.screen_stack[0].query_one(TabbedContent).active = "findings"
            self.update_targets()
        elif self.selected_pk is not None:
            self.evidence_generation += 1
            self.fetch_evidence(
                self.selected_pk, str(event.row_key.value), self.evidence_generation
            )

    @work(thread=True, exclusive=True, group="evidence")
    def fetch_evidence(self, pk: int, finding_id: str, generation: int) -> None:
        try:
            item = self.service.finding(pk, finding_id)
            self._post_ui(
                self.apply_evidence,
                pk,
                generation,
                finding_summary(item),
                json.dumps(item, indent=2),
            )
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self._post_ui(self.notify, str(exc), severity="error")

    def apply_evidence(self, pk: int, generation: int, text: str, raw: str = "") -> None:
        if pk == self.selected_pk and generation == self.evidence_generation:
            self.evidence_text, self.evidence_raw = text, raw
            self.raw_evidence = False
            screen = self.screen_stack[0]
            screen.query_one("#evidence", Static).update(text)
            screen.query_one("#finding-table", DataTable).display = False
            screen.query_one("#filter", Input).display = False
            screen.query_one("#paging", Horizontal).display = False
            screen.query_one("#detail-hint", Static).display = True
            pane = screen.query_one("#evidence-pane", DetailPane)
            pane.display = True
            pane.scroll_home(animate=False)
            pane.focus()

    def show_activity(self, pk: int) -> None:
        self.activity_pk = pk
        self.activity_generation += 1
        if self.scanning and pk == self.active_pk:
            screen = self.screen_stack[0]
            log = screen.query_one("#progress-log", Log)
            log.clear()
            log.write_lines(self.active_log)
        else:
            self.screen_stack[0].query_one("#progress-log", Log).clear()
            self.screen_stack[0].query_one("#run-status", Static).update(
                "Loading the selected run's retained activity…"
            )
            self.fetch_saved_progress(pk, self.activity_generation)

    @work(thread=True, exclusive=True, group="saved-progress")
    def fetch_saved_progress(self, pk: int, generation: int) -> None:
        try:
            activity = self.service.activity(pk)
            self._post_ui(self.apply_saved_progress, pk, generation, activity)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self._post_ui(self.notify, str(exc), severity="error")

    def apply_saved_progress(self, pk: int, generation: int, activity: dict[str, Any]) -> None:
        if pk != self.activity_pk or generation != self.activity_generation:
            return
        info = activity["result"]
        self.screen_stack[0].query_one("#run-status", Static).update(
            f"Saved activity · {info['run_id']}: {info['status']} · {info['findings']} findings"
        )
        log = self.screen_stack[0].query_one("#progress-log", Log)
        log.clear()
        log.write_lines(
            [
                f"{e['stage'].replace('_', ' ')} · {e['status']} · {e['message']}"
                for e in activity["events"]
            ]
            + result_lines(info)
        )

    def enable_edits(self) -> None:
        self.ready = True

    @on(Input.Changed)
    @on(Select.Changed)
    def remember_edits(self, event: Input.Changed | Select.Changed) -> None:
        if self.ready:
            widget = event.input if isinstance(event, Input.Changed) else event.select
            if widget.id:
                self.edited.add(widget.id)
                if widget.id in {
                    "checkout",
                    "commit",
                    "workdir",
                    "profile",
                    "config-path",
                    "timeout",
                    "max-files",
                    "output",
                    "timezone",
                    "threshold",
                    "dirty",
                    "laya",
                    "laya-config-path",
                }:
                    self.reviewed = None
                    self.screen_stack[0].query_one("#start", Button).disabled = True
                    self.screen_stack[0].query_one("#effective", Static).update(
                        "Settings changed. Ctrl+E reviews the current checkout and options."
                    )

    def capture_config(self) -> ReviewSignature:
        screen = self.screen_stack[0]

        def numeric(value: str) -> int | str:
            try:
                return int(value)
            except ValueError:
                return value

        choices: dict[str, tuple[str, Any]] = {
            "output": ("output_dir", screen.query_one("#output", Input).value),
            "timezone": ("timezone", screen.query_one("#timezone", Input).value),
            "timeout": ("timeout", numeric(screen.query_one("#timeout", Input).value)),
            "max-files": ("max_files", numeric(screen.query_one("#max-files", Input).value)),
            "laya-config-path": (
                "laya_config_path",
                screen.query_one("#laya-config-path", Input).value or None,
            ),
            "threshold": ("fail_on", screen.query_one("#threshold", Select).value),
            "dirty": ("allow_dirty", screen.query_one("#dirty", Select).value == "dirty"),
            "laya": ("laya", screen.query_one("#laya", Select).value == "on"),
        }
        defaults = ScanConfig()
        flags = {
            name: value
            for widget, (name, value) in choices.items()
            if widget in self.edited or value != getattr(defaults, name)
        }
        return (
            screen.query_one("#checkout", Input).value,
            str(screen.query_one("#profile", Select).value),
            screen.query_one("#config-path", Input).value or None,
            flags,
            screen.query_one("#commit", Input).value,
            screen.query_one("#workdir", Input).value,
        )

    @on(Button.Pressed)
    def button(self, event: Button.Pressed) -> None:
        try:
            if event.button.id == "review":
                selected = self.capture_config()
                self.reviewed = None
                self.screen_stack[0].query_one("#start", Button).disabled = True
                self.screen_stack[0].query_one("#effective", Static).update(
                    "Resolving checkout and effective settings..."
                )
                if self.starting_service:
                    self.pending_review = selected
                else:
                    self.review_checkout(selected)
            elif event.button.id == "start" and not self.scanning:
                if self.review_signature != self.capture_config():
                    raise ValueError("Settings changed; review the effective configuration again")
                self.begin()
                self.execute_scan()
            elif event.button.id == "cancel":
                self.action_cancel()
            elif event.button.id == "retry":
                self.action_retry()
            elif event.button.id == "export":
                self.action_export()
            elif event.button.id == "key-save":
                self.save_key(
                    self.screen_stack[0].query_one("#key-name", Input).value,
                    self.screen_stack[0].query_one("#key-value", Input).value,
                )
            elif event.button.id in {"previous", "next"} and self.selected_pk is not None:
                self.page_offset = max(
                    0, self.page_offset + (200 if event.button.id == "next" else -200)
                )
                self.load_findings(self.selected_pk)
        except (ValueError, OSError) as exc:
            self.notify(f"{exc}. {recovery_advice(str(exc))}", severity="error")

    @work(thread=True, exclusive=True, group="review")
    def review_checkout(self, signature: ReviewSignature) -> None:
        try:
            checkout, profile, path, flags, commit, workdir = signature
            source = resolve_source(checkout, workdir or "harness", commit=commit)
            selected = (source.checkout, resolve_config(profile, path, **flags))
            manifest = checkout_manifest(
                *selected, expected=source.commit, excluded=self.service.runtime_paths(selected[1])
            )
            summary = (
                "Repository: "
                + source.repo_url
                + "\n"
                + review_summary(source.checkout, selected[1], manifest)
            )
            raw = json.dumps(
                {"configuration": selected[1].model_dump(), "manifest": manifest}, indent=2
            )
            self._post_ui(self.apply_review, signature, selected, source, summary, raw)
        except (ValueError, OSError) as exc:
            self._post_ui(self.review_failed, signature, str(exc))

    def review_failed(self, signature: ReviewSignature, message: str) -> None:
        if signature == self.capture_config():
            screen = self.screen_stack[0]
            screen.query_one("#effective", Static).update(
                f"Review failed: {message}\n{recovery_advice(message)}"
            )
            screen.query_one("#review-pane", DetailPane).display = True
            screen.query_one("#review-pane", DetailPane).focus()

    def apply_review(
        self,
        signature: ReviewSignature,
        selected: tuple[str, ScanConfig],
        source: LocalSource | RemoteSource,
        summary: str,
        raw: str = "",
    ) -> None:
        if signature == self.capture_config():
            self.reviewed = selected
            self.source = source
            self.review_signature = signature
            self.review_text, self.review_raw = summary, raw
            self.raw_review = False
            self.screen_stack[0].query_one("#effective", Static).update(summary)
            self.screen_stack[0].query_one("#start", Button).disabled = False
            self.screen_stack[0].query_one("#review-pane", DetailPane).display = True
            self.screen_stack[0].query_one("#review-pane", DetailPane).focus()

    def begin(self) -> None:
        self.scanning = True
        self.cancel_pending = False
        self.cancel_signal.clear()
        self.active_pk = None
        self.activity_pk = None
        self.activity_generation += 1
        self.active_log = []
        self.active_result = None
        self.follow_active = True
        self.scan_generation += 1
        self.activity_polling = False
        self.partial_findings = None
        self.current_stage = "Preparing checkout"
        self.active_run_id = ""
        self.started = time.monotonic()
        self.screen_stack[0].query_one(TabbedContent).active = "progress"
        self.screen_stack[0].query_one("#progress-log", Log).clear()
        self.screen_stack[0].query_one("#run-status", Static).update("Preparing the checkout…")
        self.screen_stack[0].query_one("#cancel", Button).disabled = False
        self.update_targets()

    @work(thread=True)
    def execute_scan(self, retry: int | None = None) -> None:
        worker = get_current_worker()
        while not self.service_ready.wait(0.05):
            if worker.is_cancelled:
                return

        def progress(event: ProgressEvent) -> None:
            self.post_message(self.Progress(event))

        try:
            if retry is not None:
                result = self.service.retry(
                    retry,
                    progress,
                    cancel_signal=lambda: worker.is_cancelled or self.cancel_signal.is_set(),
                )
            else:
                assert self.reviewed is not None
                result = self.service.run(
                    *self.reviewed,
                    repo=self.source.repo_url if self.source else "local",
                    expected_commit=self.source.commit if self.source else "",
                    on_event=progress,
                    cancel_signal=lambda: worker.is_cancelled or self.cancel_signal.is_set(),
                )
        except Exception as exc:  # noqa: BLE001 | application boundary preserves partial evidence
            result = {"status": "failed", "exit_code": 2, "errors": [str(exc)]}
        self.post_message(self.Finished(result))

    def on_scan_app_progress(self, message: Progress) -> None:
        if not self.is_running or not self.screen_stack:
            return
        event = message.event
        self.current_stage = event.stage.replace("_", " ")
        self.active_run_id = event.run_id
        if event.pk is not None and self.active_pk is None:
            self.active_pk = event.pk
            if self.follow_active:
                self.selected_pk, self.activity_pk = event.pk, event.pk
                self.viewed_run_id = event.run_id
                self.page_offset = 0
                self.update_targets()
        if self.selected_pk == self.active_pk:
            self.findings_dirty = True
        line = f"{event.stage.replace('_', ' ')} · {event.status} · {event.message}"
        self.active_log.append(line)
        if self.activity_pk == self.active_pk:
            self.screen_stack[0].query_one("#progress-log", Log).write_line(line)

    def on_scan_app_finished(self, message: Finished) -> None:
        if not self.is_running or not self.screen_stack:
            return
        self.scanning = False
        self.active_result = message.result
        self.screen_stack[0].query_one("#cancel", Button).disabled = True
        if self.activity_pk == self.active_pk:
            self.screen_stack[0].query_one("#run-status", Static).update(
                f"{message.result.get('run_id', '')}: {message.result['status']} | "
                f"gate {message.result.get('gate', 'failed')} | exit {message.result['exit_code']} | "
                f"{message.result.get('findings', 0)} findings"
            )
            self.screen_stack[0].query_one("#progress-log", Log).write_lines(
                result_lines(message.result)
            )
        self.action_refresh()
        if self.active_pk and self.selected_pk == self.active_pk:
            self.load_findings(self.active_pk)
        self.update_targets()
        if self.quit_after_scan:
            self.exit()

    def action_cancel(self) -> None:
        self.cancel_pending = self.scanning
        if self.scanning:
            self.cancel_signal.set()
        if self.active_pk is not None:
            self.persist_cancel(self.active_pk)

    @work(thread=True, group="cancel")
    def persist_cancel(self, pk: int) -> None:
        self.service.cancel(pk)

    @work(thread=True, exclusive=True, group="export")
    def export_run(self, pk: int, fmt: ExportFormat, output: str) -> None:
        try:
            path = self.service.export(pk, fmt, output)
            self._post_ui(self.show_export, path)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self._post_ui(self.notify, str(exc), severity="error")

    def show_export(self, path: str) -> None:
        self.screen_stack[0].query_one("#export-path", Static).update(path)

    async def action_quit(self) -> None:
        if self.scanning:

            def chosen(cancel: bool | None) -> None:
                if cancel:
                    self.quit_after_scan = True
                    self.action_cancel()

            self.push_screen(QuitScan(), chosen)
        else:
            self.exit()
