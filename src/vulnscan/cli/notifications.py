"""Explicit event selection for outbound scan notifications (FR-75)."""

from __future__ import annotations

import json
from typing import Any

import typer

from vulnscan.notifications.events import EVENT_LABELS
from vulnscan.notifications.service import deliveries, send_selected
from vulnscan.notifications.settings import load_settings, save_settings
from vulnscan.storage.database import init_db

app = typer.Typer(help="Choose Telegram/Discord events and review pending digests.")


def _choose(prompt: str, options: list[str], *, default: str = "") -> list[str]:
    labels = {str(kind): label for kind, label in EVENT_LABELS.items()}
    for index, option in enumerate(options, 1):
        typer.echo(f"  {index}. {labels.get(option, option)}")
    raw = typer.prompt(prompt + " (comma-separated numbers; blank = none)", default=default)
    try:
        indices = [int(part.strip()) - 1 for part in raw.split(",") if part.strip()]
        if any(index < 0 or index >= len(options) for index in indices):
            raise ValueError
        return list(dict.fromkeys(options[index] for index in indices))
    except ValueError:
        raise typer.BadParameter("Choose numbers from the displayed list") from None


@app.command("configure")
def configure() -> None:
    """Ask which destinations and events to enable; never requests secret values."""
    try:
        cfg = load_settings().model_dump()
        mode = typer.prompt("Delivery mode (manual/automatic)", default=cfg["mode"]).strip()
        if mode not in {"manual", "automatic"}:
            raise ValueError("Choose manual or automatic")
        cfg["mode"] = mode
        for channel in ("telegram", "discord"):
            cfg[channel]["enabled"] = typer.confirm(
                f"Enable {channel.title()}?", default=cfg[channel]["enabled"]
            )
        for channel in ("telegram", "discord"):
            if cfg[channel]["enabled"]:
                cfg[channel]["events"] = _choose(
                    f"Which events should {channel.title()} receive?", list(EVENT_LABELS)
                )
        save_settings(cfg)
    except (OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from None
    typer.echo("Notification preferences saved. No messages were sent.")
    typer.echo(
        "Save credentials with `env set`: DEVSEC_TELEGRAM_BOT_TOKEN, DEVSEC_TELEGRAM_CHAT_ID, DEVSEC_DISCORD_WEBHOOK_SECRET."
    )


@app.command("settings")
def settings() -> None:
    """Show event preferences and environment references only."""
    try:
        typer.echo(load_settings().model_dump_json(indent=2))
    except (ValueError, OSError):
        typer.echo("Cannot load notification settings", err=True)
        raise typer.Exit(1) from None


def review_pending(db_path: str, run_id: str) -> dict[str, Any]:
    receipt = deliveries(db_path, run_id)
    pending = [row for row in receipt["deliveries"] if row["status"] == "pending"]
    if not pending:
        typer.echo(json.dumps(receipt, indent=2))
        return receipt
    channels = _choose(
        "Which destinations should receive this scan?", [r["channel"] for r in pending]
    )
    if not channels:
        typer.echo("Nothing sent; drafts retained.")
        return receipt
    events = list(
        dict.fromkeys(
            e["kind"] for row in pending if row["channel"] in channels for e in row["events"]
        )
    )
    for row in pending:
        if row["channel"] in channels:
            for event in row["events"]:
                typer.echo(f"{row['channel']}: {event['message']}")
    chosen = _choose("Which events should be sent?", events)
    if not chosen:
        typer.echo("Nothing sent; drafts retained.")
        return receipt
    channels = [
        row["channel"]
        for row in pending
        if row["channel"] in channels and any(e["kind"] in chosen for e in row["events"])
    ]
    if not typer.confirm("Send these selected summaries now?", default=False):
        typer.echo("Nothing sent; drafts retained.")
        return receipt
    receipt = send_selected(db_path, run_id, chosen, channels)
    typer.echo(json.dumps(receipt, indent=2))
    return receipt


@app.command("review")
def review(run_id: str, db_path: str = typer.Option("vulnscan.db", "--db-path")) -> None:
    """Preview a pending scan digest, choose events and explicitly send."""
    init_db(db_path)
    try:
        review_pending(db_path, run_id)
    except (ValueError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from None


@app.command("send")
def send(
    run_id: str,
    events: str = typer.Option(..., "--events", help="Comma-separated event IDs."),
    channels: str = typer.Option(..., "--channels", help="telegram,discord or either."),
    db_path: str = typer.Option("vulnscan.db", "--db-path"),
    retry: bool = typer.Option(
        False,
        "--retry",
        help="Explicit retry; an unknown previous delivery may already exist remotely.",
    ),
) -> None:
    """Send an explicit selection; unknown deliveries are never retried implicitly."""
    init_db(db_path)
    try:
        result = send_selected(
            db_path,
            run_id,
            [e.strip() for e in events.split(",") if e.strip()],
            [c.strip() for c in channels.split(",") if c.strip()],
            retry=retry,
        )
    except (ValueError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from None
    typer.echo(json.dumps(result, indent=2))
    if any(row["status"] != "sent" for row in result["deliveries"]):
        raise typer.Exit(1)
