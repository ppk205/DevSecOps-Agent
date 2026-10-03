"""Keyboard-accessible persistent scan workspace (FR-71, QR-21)."""

from __future__ import annotations

import json
import time
from datetime import datetime
from threading import Event
from typing import Any, ClassVar
from zoneinfo import ZoneInfo

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widgets import (
    Button,
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
from vulnscan.version import APP_VERSION


class QuitScan(ModalScreen[bool]):
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
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+n", "setup", "New scan"),
        ("ctrl+r", "refresh", "History"),
        ("ctrl+x", "cancel", "Cancel scan"),
    ]
    CSS = """
    TabPane { padding: 1; }
    Input, Select, Button { margin-bottom: 1; }
    DataTable { height: 1fr; min-height: 6; }
    #evidence { height: auto; min-height: 5; }
    #effective { height: auto; }
    #progress-log { height: 1fr; }
    #paging { height: 3; }
    #paging Button { margin-right: 1; }
    QuitScan { align: center middle; background: $background 80%; }
    QuitScan VerticalScroll { width: 64; height: 14; border: thick $accent; padding: 1; }
    """

    class Progress(Message):
        def __init__(self, event: ProgressEvent) -> None:
            self.event = event
            super().__init__()

    class Finished(Message):
        def __init__(self, result: dict[str, Any]) -> None:
            self.result = result
            super().__init__()

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
        self.reviewed: tuple[str, ScanConfig] | None = None
        self.review_signature: tuple[str, str, str | None, dict[str, Any]] | None = None
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
        self.pending_review: tuple[str, str, str | None, dict[str, Any]] | None = None
        self.service_ready = Event()

    @property
    def service(self) -> ScanService:
        if self._service is None:
            raise RuntimeError("Scan workspace is still loading")
        return self._service

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Overview", id="overview"):
                yield Static("Checking scanner availability…", id="availability", markup=False)
                yield DataTable(id="history", cursor_type="row")
                yield Button("Retry selected run", id="retry")
            with TabPane("Targets and setup", id="setup"), VerticalScroll():
                yield Label("Local Git checkout")
                yield Input(".", id="checkout")
                yield Select(
                    [
                        ("Fast: Semgrep + Gitleaks", "fast"),
                        ("Full: isolated Maven + all scanners", "full"),
                    ],
                    value="fast",
                    allow_blank=False,
                    id="profile",
                )
                yield Label("Optional versioned configuration file")
                yield Input(placeholder="config/scan.json", id="config-path")
                yield Label("Wall-clock limit (seconds)")
                yield Input("600", id="timeout")
                yield Label("Maximum source files")
                yield Input("100000", id="max-files")
                yield Select(
                    [
                        ("Clean checkout required", "clean"),
                        ("Allow dirty local contents and record hashes", "dirty"),
                    ],
                    value="clean",
                    allow_blank=False,
                    id="dirty",
                )
                yield Button("Review effective configuration", id="review")
                yield Static("Review settings before starting.", id="effective", markup=False)
                yield Button("Start reviewed scan", id="start", variant="primary", disabled=True)
            with TabPane("Run progress", id="progress"):
                yield Static("Idle", id="run-status", markup=False)
                yield Log(id="progress-log")
                yield Button("Cancel scan", id="cancel", variant="error")
            with TabPane("Findings and evidence", id="findings"):
                yield Input(
                    placeholder="Search severity, CWE, scanner, status, evidence…", id="filter"
                )
                yield DataTable(id="finding-table", cursor_type="row")
                with Horizontal(id="paging"):
                    yield Button("Previous", id="previous", disabled=True)
                    yield Button("Next", id="next", disabled=True)
                    yield Static("0 findings", id="page-status", markup=False)
                with VerticalScroll():
                    yield Static(
                        "Select a finding to inspect evidence and provenance.",
                        id="evidence",
                        markup=False,
                    )
            with TabPane("Settings and reports", id="settings"), VerticalScroll():
                yield Label("Artifact directory")
                yield Input("artifacts", id="output")
                yield Label("Display timezone")
                yield Input("Asia/Saigon", id="timezone")
                yield Select(
                    [(s.title(), s) for s in ["critical", "high", "medium", "low", "info", "none"]],
                    value="high",
                    allow_blank=False,
                    id="threshold",
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
                yield Select(
                    [(f.value.upper(), f.value) for f in ExportFormat],
                    value="json",
                    allow_blank=False,
                    id="format",
                )
                yield Button("Export selected run", id="export")
                yield Static("No export yet", id="export-path", markup=False)
        yield Footer()

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

    @work(thread=True, group="initialize")
    def initialize(self) -> None:
        try:
            if self._service is None:
                self._service = ScanService(self.db_path)
            self.service.recover()
            self.service_ready.set()
            self.call_from_thread(self.initialized)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self.call_from_thread(self.notify, str(exc), severity="error")

    def initialized(self) -> None:
        self.starting_service = False
        self.action_refresh()
        self.probe()
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
        self.call_from_thread(self.show_availability, "\n".join(labels))

    def show_availability(self, value: str) -> None:
        self.screen_stack[0].query_one("#availability", Static).update(value)

    def action_setup(self) -> None:
        self.screen_stack[0].query_one(TabbedContent).active = "setup"

    def action_refresh(self) -> None:
        if self.starting_service:
            return
        self.history_generation += 1
        self.fetch_history(self.history_generation)

    @work(thread=True, exclusive=True, group="history")
    def fetch_history(self, generation: int) -> None:
        try:
            rows = self.service.history()
            self.call_from_thread(self.apply_history, generation, rows)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self.call_from_thread(self.notify, str(exc), severity="error")

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

    def tick(self) -> None:
        if self.scanning:
            self.screen_stack[0].query_one("#run-status", Static).update(
                f"Running • {time.monotonic() - self.started:.0f}s • partial evidence is saved"
            )
            if (
                self.active_pk is not None
                and self.selected_pk == self.active_pk
                and self.findings_dirty
                and self.screen_stack[0].query_one(TabbedContent).active == "findings"
            ):
                self.load_findings(self.active_pk)

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
            self.call_from_thread(self.apply_findings, pk, generation, page)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self.call_from_thread(self.notify, str(exc), severity="error")

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
            self.page_offset = 0
            self.items = []
            self.evidence_generation += 1
            self.screen_stack[0].query_one("#evidence", Static).update(
                "Select a finding to inspect evidence."
            )
            self.load_findings(self.selected_pk)
            if not self.scanning:
                self.fetch_saved_progress(self.selected_pk)
            self.screen_stack[0].query_one(TabbedContent).active = "findings"
        elif self.selected_pk is not None:
            self.evidence_generation += 1
            self.fetch_evidence(
                self.selected_pk, str(event.row_key.value), self.evidence_generation
            )

    @work(thread=True, exclusive=True, group="evidence")
    def fetch_evidence(self, pk: int, finding_id: str, generation: int) -> None:
        try:
            text = json.dumps(self.service.finding(pk, finding_id), indent=2)
            self.call_from_thread(self.apply_evidence, pk, generation, text)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self.call_from_thread(self.notify, str(exc), severity="error")

    def apply_evidence(self, pk: int, generation: int, text: str) -> None:
        if pk == self.selected_pk and generation == self.evidence_generation:
            self.screen_stack[0].query_one("#evidence", Static).update(text)

    @work(thread=True, exclusive=True, group="saved-progress")
    def fetch_saved_progress(self, pk: int) -> None:
        info = self.service.summary(pk)
        events = self.service.progress_since(pk)
        self.call_from_thread(self.apply_saved_progress, pk, info, events)

    def apply_saved_progress(self, pk: int, info: dict[str, Any], events: dict[str, Any]) -> None:
        if pk != self.selected_pk or self.scanning:
            return
        self.screen_stack[0].query_one("#run-status", Static).update(
            f"{info['run_id']}: {info['status']}"
        )
        log = self.screen_stack[0].query_one("#progress-log", Log)
        log.clear()
        log.write_lines([f"{e['stage']}: {e['status']} {e['message']}" for e in events["events"]])

    def enable_edits(self) -> None:
        self.ready = True

    @on(Input.Changed)
    @on(Select.Changed)
    def remember_edits(self, event: Input.Changed | Select.Changed) -> None:
        if self.ready:
            widget = event.input if isinstance(event, Input.Changed) else event.select
            if widget.id:
                self.edited.add(widget.id)

    def capture_config(self) -> tuple[str, str, str | None, dict[str, Any]]:
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
            elif event.button.id == "retry" and self.selected_pk is not None and not self.scanning:
                self.begin()
                self.execute_scan(self.selected_pk)
            elif event.button.id == "export" and self.selected_pk is not None:
                self.export_run(
                    self.selected_pk,
                    ExportFormat(self.screen_stack[0].query_one("#format", Select).value),
                    self.screen_stack[0].query_one("#output", Input).value,
                )
            elif event.button.id in {"previous", "next"} and self.selected_pk is not None:
                self.page_offset = max(
                    0, self.page_offset + (200 if event.button.id == "next" else -200)
                )
                self.load_findings(self.selected_pk)
        except (ValueError, OSError) as exc:
            self.notify(str(exc), severity="error")

    @work(thread=True, exclusive=True, group="review")
    def review_checkout(self, signature: tuple[str, str, str | None, dict[str, Any]]) -> None:
        try:
            checkout, profile, path, flags = signature
            selected = (checkout, resolve_config(profile, path, **flags))
            manifest = checkout_manifest(
                *selected, excluded=self.service.runtime_paths(selected[1])
            )
            summary = (
                f"Commit: {manifest['commit']} | {len(manifest['inventory'])} Java/JSP files\n"
                + selected[1].model_dump_json(indent=2)
            )
            self.call_from_thread(self.apply_review, signature, selected, summary)
        except (ValueError, OSError) as exc:
            self.call_from_thread(self.review_failed, signature, str(exc))

    def review_failed(
        self, signature: tuple[str, str, str | None, dict[str, Any]], message: str
    ) -> None:
        if signature == self.capture_config():
            self.screen_stack[0].query_one("#effective", Static).update(message)

    def apply_review(
        self,
        signature: tuple[str, str, str | None, dict[str, Any]],
        selected: tuple[str, ScanConfig],
        summary: str,
    ) -> None:
        if signature == self.capture_config():
            self.reviewed = selected
            self.review_signature = signature
            self.screen_stack[0].query_one("#effective", Static).update(summary)
            self.screen_stack[0].query_one("#start", Button).disabled = False

    def begin(self) -> None:
        self.scanning = True
        self.cancel_pending = False
        self.cancel_signal.clear()
        self.active_pk = None
        self.started = time.monotonic()
        self.screen_stack[0].query_one(TabbedContent).active = "progress"
        self.screen_stack[0].query_one("#progress-log", Log).clear()

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
                    on_event=progress,
                    cancel_signal=lambda: worker.is_cancelled or self.cancel_signal.is_set(),
                )
        except Exception as exc:  # noqa: BLE001 | application boundary preserves partial evidence
            result = {"status": "failed", "exit_code": 2, "errors": [str(exc)]}
        self.post_message(self.Finished(result))

    def on_scan_app_progress(self, message: Progress) -> None:
        event = message.event
        if event.pk is not None and self.active_pk is None:
            self.active_pk = event.pk
            self.selected_pk = event.pk
            self.page_offset = 0
        if self.selected_pk == self.active_pk:
            self.findings_dirty = True
        self.screen_stack[0].query_one("#progress-log", Log).write_line(
            f"{event.stage}: {event.status} {event.message}"
        )

    def on_scan_app_finished(self, message: Finished) -> None:
        self.scanning = False
        self.screen_stack[0].query_one("#run-status", Static).update(
            f"{message.result.get('run_id', '')}: {message.result['status']} | "
            f"gate {message.result.get('gate', 'failed')} | exit {message.result['exit_code']} | "
            f"{message.result.get('findings', 0)} findings"
        )
        for error in message.result.get("errors", []):
            self.screen_stack[0].query_one("#progress-log", Log).write_line(error)
        self.action_refresh()
        if self.active_pk and self.selected_pk == self.active_pk:
            self.load_findings(self.active_pk)
        self.active_pk = None
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
            self.call_from_thread(self.show_export, path)
        except Exception as exc:  # noqa: BLE001 - UI worker boundary
            self.call_from_thread(self.notify, str(exc), severity="error")

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
