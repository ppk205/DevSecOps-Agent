"""Operator notification preferences and manual delivery for the Textual fallback."""

from __future__ import annotations

from typing import Any, ClassVar

from textual import on, work
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Select, SelectionList, Static

from vulnscan.notifications.events import EVENT_LABELS
from vulnscan.notifications.service import handle


class NotificationsDialog(ModalScreen[None]):
    BINDINGS: ClassVar = [("escape", "close", "Close")]
    DEFAULT_CSS = """
    NotificationsDialog { align: center middle; }
    NotificationsDialog > VerticalScroll {
        width: 90%; height: 90%; border: solid $accent; padding: 1;
        background: $surface;
    }
    NotificationsDialog SelectionList { height: auto; max-height: 10; }
    """

    def __init__(self, db_path: str, data: dict[str, Any]) -> None:
        super().__init__()
        self.db_path, self.data = db_path, data

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Notifications · choose what to send")
            if "settings" in self.data:
                cfg = self.data["settings"]
                yield Select(
                    [("Ask after each scan", "manual"), ("Send automatically", "automatic")],
                    value=cfg["mode"],
                    allow_blank=False,
                    id="delivery-mode",
                )
                yield SelectionList(
                    *[
                        (c.title() + " enabled", c, cfg[c]["enabled"])
                        for c in ("telegram", "discord")
                    ],
                    id="enabled-channels",
                )
                for channel in ("telegram", "discord"):
                    yield Label(channel.title() + " events")
                    yield SelectionList(
                        *[
                            (label, kind, kind in cfg[channel]["events"])
                            for kind, label in EVENT_LABELS.items()
                        ],
                        id=f"{channel}-events",
                    )
                yield Static(
                    "Credentials: masked Keys controls or CLI env set. Preferences contain references only."
                )
                yield Button("Save preferences", id="submit-notifications")
            else:
                pending = [d for d in self.data["deliveries"] if d["status"] == "pending"]
                events = {e["kind"]: e["message"] for d in pending for e in d["events"]}
                for row in self.data["deliveries"]:
                    yield Static(f"{row['channel']}: {row['status']}")
                yield SelectionList(
                    *[(d["channel"], d["channel"], False) for d in pending], id="send-channels"
                )
                yield SelectionList(
                    *[(text, kind, False) for kind, text in events.items()], id="send-events"
                )
                yield Button("Send selected summaries now", id="submit-notifications")
            yield Static(
                "No messages sent on opening or closing this screen.", id="notification-status"
            )
            yield Button("Close", id="close-notifications")

    def action_close(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#close-notifications")
    def close_clicked(self) -> None:
        self.action_close()

    @on(Button.Pressed, "#submit-notifications")
    def submit(self) -> None:
        if "settings" in self.data:
            cfg = self.data["settings"]
            cfg["mode"] = str(self.query_one("#delivery-mode", Select).value)
            enabled = self.query_one("#enabled-channels", SelectionList).selected
            for channel in ("telegram", "discord"):
                cfg[channel]["enabled"] = channel in enabled
                cfg[channel]["events"] = self.query_one(
                    f"#{channel}-events", SelectionList
                ).selected
            params = {"action": "save", "settings": cfg}
        else:
            events = self.query_one("#send-events", SelectionList).selected
            channels = self.query_one("#send-channels", SelectionList).selected
            if not events or not channels:
                self.query_one("#notification-status", Static).update(
                    "Choose events and destinations before sending."
                )
                return
            channels = [
                row["channel"]
                for row in self.data["deliveries"]
                if row["status"] == "pending"
                and row["channel"] in channels
                and any(e["kind"] in events for e in row["events"])
            ]
            params = {
                "action": "send",
                "run_id": self.data["run_id"],
                "events": events,
                "channels": channels,
            }
        self.query_one("#submit-notifications", Button).disabled = True
        self.deliver(params)

    @work(thread=True, group="notification-delivery", exclusive=True)
    def deliver(self, params: dict[str, Any]) -> None:
        try:
            result = handle(self.db_path, params)
            message = (
                "Preferences saved. No messages sent."
                if params["action"] == "save"
                else "; ".join(f"{row['channel']}: {row['status']}" for row in result["deliveries"])
            )
        except (ValueError, OSError):
            message = "Notification operation failed; check configuration and retained receipts."
        self.app.call_from_thread(self.show_result, message)

    def show_result(self, message: str) -> None:
        if self.is_mounted:
            self.query_one("#notification-status", Static).update(message)
