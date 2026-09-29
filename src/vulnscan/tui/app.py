"""Keyboard-accessible persistent scan workspace (FR-71, QR-21).

Friendly first-run experience: opens on a Welcome tab with onboarding,
has a dedicated API Keys tab for managing secrets without touching the shell.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any, ClassVar
from zoneinfo import ZoneInfo

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
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
from vulnscan.infra.envfile import EnvFile
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
    #welcome-text { padding: 1 2; }
    #keys-status { height: auto; min-height: 3; }
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
        self.service = service or ScanService(db_path)
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

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            # ── Welcome / Onboarding ──────────────────────────────────
            with TabPane("Welcome", id="welcome"):
                yield Static(
                    f"Welcome to DevSecOps Agent {APP_VERSION}\n\n"
                    "This tool scans Java/JSP source code for security vulnerabilities.\n\n"
                    "Quick start:\n"
                    "  1. Go to the API Keys tab to save an AI provider key (optional)\n"
                    "  2. Go to the Scan tab, enter a repo URL or local path, and start\n"
                    "  3. View results in the Findings tab\n\n"
                    "Keyboard shortcuts:\n"
                    "  Ctrl+N  New scan    Ctrl+R  Refresh history\n"
                    "  Ctrl+X  Cancel scan  Ctrl+Q  Quit",
                    id="welcome-text",
                    markup=False,
                )
                yield Static("Checking scanner availability…", id="availability", markup=False)
                yield DataTable(id="history", cursor_type="row")
                yield Button("Retry selected run", id="retry")
            # ── Scan setup ────────────────────────────────────────────
            with TabPane("Scan", id="setup"), VerticalScroll():
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
            # ── API Keys ──────────────────────────────────────────────
            with TabPane("API Keys", id="keys"), VerticalScroll():
                yield Label("Save an API key to the project .env file")
                yield Input(placeholder="OPENAI_API_KEY", id="key-name")
                yield Input(placeholder="sk-...", id="key-value", password=True)
                yield Button("Save key", id="save-key", variant="primary")
                yield Static("", id="keys-status", markup=False)
                yield Label("Stored keys (values never shown):")
                yield Static("No keys stored", id="keys-list", markup=False)
            # ── Run progress ──────────────────────────────────────────
            with TabPane("Run", id="progress"):
                yield Static("Idle", id="run-status", markup=False)
                yield Log(id="progress-log")
                yield Button("Cancel scan", id="cancel", variant="error")
            # ── Findings ──────────────────────────────────────────────
            with TabPane("Findings", id="findings"):
                yield Input(
                    placeholder="Search severity, CWE, scanner, status, evidence…", id="filter"
                )
                yield DataTable(id="finding-table", cursor_type="row")
                with VerticalScroll():
                    yield Static(
                        "Select a finding to inspect evidence and provenance.",
                        id="evidence",
                        markup=False,
                    )
            # ── Settings / Reports ────────────────────────────────────
            with TabPane("Settings", id="settings"), VerticalScroll():
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
        # Load .env so API keys saved via CLI or TUI are available
        EnvFile().load_into_environ()

        self.screen_stack[0].query_one("#history", DataTable).add_columns(
            "ID", "Run", "Status", "Attempt", "Started"
        )
        self.screen_stack[0].query_one("#finding-table", DataTable).add_columns(
            "Severity", "CWE", "Status", "Scanner", "Title"
        )
        self.refresh_keys_list()
        self.check_availability()

    def refresh_keys_list(self) -> None:
        names = EnvFile().names()
        widget = self.screen_stack[0].query_one("#keys-list", Static)
        if not names:
            widget.update("No keys stored")
        else:
            lines = []
            for key in names:
                live = bool(os.environ.get(key, "").strip())
                source = "env" if live else ".env"
                lines.append(f"  • {key} ({source})")
            widget.update("\n".join(lines))

    def check_availability(self) -> None:
        labels = []
        for adapter in self.service.registry.adapters.values():
            cap = adapter.capabilities()
            labels.append(
                f"{cap.tool.value}: available"
                if cap.available
                else f"unavailable — install {cap.binary or cap.tool.value} on PATH"
            )
        self.screen_stack[0].query_one("#availability", Static).update("\n".join(labels))

    def action_setup(self) -> None:
        self.screen_stack[0].query_one(TabbedContent).active = "setup"

    def action_refresh(self) -> None:
        table = self.screen_stack[0].query_one("#history", DataTable)
        table.clear()
        try:
            zone = ZoneInfo(self.screen_stack[0].query_one("#timezone", Input).value)
        except (ValueError, KeyError):
            zone = ZoneInfo("Asia/Saigon")
        for row in self.service.history():
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

    def tick(self) -> None:
        if self.scanning:
            self.screen_stack[0].query_one("#run-status", Static).update(
                f"Running • {time.monotonic() - self.started:.0f}s • partial evidence is saved"
            )
            if self.active_pk is not None:
                self.load_findings(self.active_pk)

    def load_findings(self, pk: int) -> None:
        self.items = self.service.detail(pk)["findings"]
        self.filter_findings()

    @on(Input.Changed, "#filter")
    def filter_findings(self) -> None:
        table = self.screen_stack[0].query_one("#finding-table", DataTable)
        table.clear()
        query = self.screen_stack[0].query_one("#filter", Input).value.lower()
        for item in self.items:
            row_text = " ".join(str(v) for v in item.values()).lower()
            if query and query not in row_text:
                continue
            table.add_row(
                str(item.get("severity", "")),
                str(item.get("cwe_category", "")),
                str(item.get("status", "")),
                str(item.get("scanner", "")),
                str(item.get("title", ""))[:60],
                key=str(item.get("finding_id", "")),
            )

    @on(DataTable.RowSelected, "#finding-table")
    def show_evidence(self, event: DataTable.RowSelected) -> None:
        finding_id = event.row_key.value
        for item in self.items:
            if str(item.get("finding_id", "")) == finding_id:
                self.screen_stack[0].query_one("#evidence", Static).update(
                    json.dumps(item, indent=2, ensure_ascii=False, default=str)[:2000]
                )
                break

    @on(Input.Changed)
    def mark_edited(self, event: Input.Changed) -> None:
        self.edited.add(event.input.id)

    @on(Select.Changed)
    def mark_select_edited(self, event: Select.Changed) -> None:
        self.edited.add(event.select.id)

    def read_config(self) -> tuple[str, ScanConfig]:
        screen = self.screen_stack[0]
        config_path = screen.query_one("#config-path", Input).value
        choices = {
            "timeout": ("timeout", int(screen.query_one("#timeout", Input).value)),
            "max_files": ("max_files", int(screen.query_one("#max-files", Input).value)),
            "dirty": ("allow_dirty", screen.query_one("#dirty", Select).value == "dirty"),
            "output": ("output_dir", screen.query_one("#output", Input).value),
            "timezone": ("timezone", screen.query_one("#timezone", Input).value),
            "fail_on": ("fail_on", screen.query_one("#threshold", Select).value),
            "laya": ("laya", screen.query_one("#laya", Select).value == "on"),
            "laya_config_path": (
                "laya_config_path",
                screen.query_one("#laya-config-path", Input).value or None,
            ),
        }
        defaults = ScanConfig()
        flags = {
            name: value
            for widget, (name, value) in choices.items()
            if widget in self.edited or value != getattr(defaults, name)
        }
        config = resolve_config(
            str(screen.query_one("#profile", Select).value),
            config_path or None,
            **flags,
        )
        return screen.query_one("#checkout", Input).value, config

    @on(Button.Pressed)
    def button(self, event: Button.Pressed) -> None:
        try:
            if event.button.id == "review":
                selected = self.read_config()
                self.reviewed = None
                self.screen_stack[0].query_one("#start", Button).disabled = True
                self.screen_stack[0].query_one("#effective", Static).update(
                    "Resolving checkout and effective settings..."
                )
                self.review_checkout(selected)
            elif event.button.id == "start" and not self.scanning:
                if self.reviewed != self.read_config():
                    raise ValueError("Settings changed; review the effective configuration again")
                self.begin()
                self.execute_scan()
            elif event.button.id == "cancel":
                self.action_cancel()
            elif event.button.id == "retry" and self.selected_pk is not None and not self.scanning:
                self.begin()
                self.execute_scan(self.selected_pk)
            elif event.button.id == "export" and self.selected_pk is not None:
                path = self.service.export(
                    self.selected_pk,
                    ExportFormat(self.screen_stack[0].query_one("#format", Select).value),
                    self.screen_stack[0].query_one("#output", Input).value,
                )
                self.screen_stack[0].query_one("#export-path", Static).update(path)
            elif event.button.id == "save-key":
                self.save_key()
        except (ValueError, OSError) as exc:
            self.notify(str(exc), severity="error")

    def save_key(self) -> None:
        name = self.screen_stack[0].query_one("#key-name", Input).value.strip().upper()
        value = self.screen_stack[0].query_one("#key-value", Input).value.strip()
        if not name or not value:
            self.screen_stack[0].query_one("#keys-status", Static).update(
                "Enter both a name and a value."
            )
            return
        try:
            path = EnvFile().set(name, value)
        except ValueError as exc:
            self.screen_stack[0].query_one("#keys-status", Static).update(str(exc))
            return
        os.environ[name] = value
        self.screen_stack[0].query_one("#key-name", Input).value = ""
        self.screen_stack[0].query_one("#key-value", Input).value = ""
        self.screen_stack[0].query_one("#keys-status", Static).update(
            f"Saved {name} to {path}"
        )
        self.refresh_keys_list()

    @work(thread=True, exclusive=True, group="review")
    def review_checkout(self, selected: tuple[str, ScanConfig]) -> None:
        try:
            manifest = checkout_manifest(
                *selected, excluded=self.service.runtime_paths(selected[1])
            )
            summary = (
                f"Commit: {manifest['commit']} | {len(manifest['inventory'])} Java/JSP files\n"
                + selected[1].model_dump_json(indent=2)
            )
            self.call_from_thread(self.apply_review, selected, summary)
        except (ValueError, OSError) as exc:
            self.call_from_thread(
                self.screen_stack[0].query_one("#effective", Static).update, str(exc)
            )

    def apply_review(self, selected: tuple[str, ScanConfig], summary: str) -> None:
        if selected == self.read_config():
            self.reviewed = selected
            self.screen_stack[0].query_one("#effective", Static).update(summary)
            self.screen_stack[0].query_one("#start", Button).disabled = False

    def begin(self) -> None:
        self.scanning = True
        self.cancel_pending = False
        self.started = time.monotonic()
        self.screen_stack[0].query_one(TabbedContent).active = "progress"
        self.screen_stack[0].query_one("#progress-log", Log).clear()

    @work(thread=True)
    def execute_scan(self, retry: int | None = None) -> None:
        worker = get_current_worker()

        def progress(event: ProgressEvent) -> None:
            self.post_message(self.Progress(event))

        try:
            if retry is not None:
                result = self.service.retry(
                    retry, progress, cancel_signal=lambda: worker.is_cancelled
                )
            else:
                assert self.reviewed is not None
                result = self.service.run(
                    *self.reviewed, on_event=progress, cancel_signal=lambda: worker.is_cancelled
                )
        except Exception as exc:  # noqa: BLE001 | application boundary preserves partial evidence
            result = {"status": "failed", "exit_code": 2, "errors": [str(exc)]}
        self.post_message(self.Finished(result))

    def on_scan_app_progress(self, message: Progress) -> None:
        event = message.event
        for row in self.service.history():
            if row["run_id"] == event.run_id:
                self.active_pk = row["id"]
                self.selected_pk = self.active_pk
                if self.cancel_pending:
                    self.service.cancel(self.active_pk)
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
        if self.active_pk:
            self.load_findings(self.active_pk)
        self.active_pk = None
        if self.quit_after_scan:
            self.exit()

    def action_cancel(self) -> None:
        self.cancel_pending = self.scanning
        if self.active_pk is not None:
            self.service.cancel(self.active_pk)

    async def action_quit(self) -> None:
        if self.scanning:

            def chosen(cancel: bool | None) -> None:
                if cancel:
                    self.quit_after_scan = True
                    self.action_cancel()

            self.push_screen(QuitScan(), chosen)
        else:
            self.exit()
