"""FR-75: trusted, opt-in outbound delivery, separate from scan/finding status."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vulnscan.contracts import Finding
from vulnscan.infra.envfile import EnvFile
from vulnscan.storage.database import get_session
from vulnscan.storage.models import FindingORM, NotificationDeliveryORM, RunORM

from .events import EVENT_LABELS, events_for_scan
from .settings import load_settings, save_settings
from .transports import DeliveryResult, send_discord, send_telegram


def _run(session: Session, identity: int | str) -> RunORM:
    query = select(RunORM).where(RunORM.public_id == str(identity))
    run = session.scalar(query)
    if run is None and str(identity).isdigit():
        run = session.get(RunORM, int(identity))
    if run is None:
        raise ValueError("Unknown scan")
    return run


def _receipt(row: NotificationDeliveryORM) -> dict[str, Any]:
    return {
        "id": row.id,
        "channel": row.channel,
        "status": row.status,
        "detail": row.detail,
        "events": json.loads(row.events_json),
        "selected_events": json.loads(row.selected_events_json),
    }


def deliveries(db_path: str, run_id: int | str) -> dict[str, Any]:
    """Read retained receipts without creating drafts or sending anything."""
    with get_session(db_path) as session:
        run = _run(session, run_id)
        rows = session.scalars(
            select(NotificationDeliveryORM)
            .where(NotificationDeliveryORM.run_id == run.id)
            .order_by(NotificationDeliveryORM.id)
        ).all()
        return {"run_id": run.public_id or str(run.id), "deliveries": [_receipt(r) for r in rows]}


def offer_run(db_path: str, run_id: int | str) -> dict[str, Any]:
    """Called at completion; saved manual rules create drafts, automatic rules send."""
    cfg = load_settings()
    channels = {"telegram": cfg.telegram, "discord": cfg.discord}
    if not any(c.enabled and c.events for c in channels.values()):
        return {"mode": cfg.mode, "status": "disabled", "deliveries": []}
    with get_session(db_path) as session:
        run = _run(session, run_id)
        if run.status not in {"completed", "failed", "cancelled", "interrupted"}:
            raise ValueError("Scan has not finished")
        pk = run.id
        summary = json.loads(run.result_json)
        summary.update(status=run.status, run_id=run.public_id or str(pk))
        findings = [
            Finding.model_validate_json(f.finding_json)
            for f in session.scalars(select(FindingORM).where(FindingORM.run_id == pk)).all()
        ]
        events = events_for_scan(summary, findings)
    for channel, config in channels.items():
        candidates = [e for e in events if e["kind"] in config.events] if config.enabled else []
        if not candidates:
            continue
        try:
            with get_session(db_path) as session:
                if (
                    session.scalar(
                        select(NotificationDeliveryORM.id).where(
                            NotificationDeliveryORM.run_id == pk,
                            NotificationDeliveryORM.channel == channel,
                        )
                    )
                    is None
                ):
                    session.add(
                        NotificationDeliveryORM(
                            run_id=pk, channel=channel, events_json=json.dumps(candidates)
                        )
                    )
        except IntegrityError:
            # A concurrent completion already retained this channel's digest.
            pass
    if cfg.mode == "automatic":
        for row in deliveries(db_path, pk)["deliveries"]:
            if row["status"] == "pending":
                send_selected(db_path, pk, [e["kind"] for e in row["events"]], [row["channel"]])
    return {"mode": cfg.mode, **deliveries(db_path, pk)}


def send_selected(
    db_path: str,
    run_id: int | str,
    event_kinds: list[str],
    channels: list[str],
    *,
    retry: bool = False,
) -> dict[str, Any]:
    """Explicit operator send. Never retry an uncertain delivery automatically."""
    if not event_kinds or not channels or set(channels) - {"telegram", "discord"}:
        raise ValueError("Choose events and destinations before sending")
    cfg = load_settings()
    rows = deliveries(db_path, run_id)["deliveries"]
    chosen = [row for row in rows if row["channel"] in channels]
    allowed: set[str] = set()
    if len(chosen) != len(set(channels)):
        raise ValueError("No notification draft for the selected destination")
    for row in chosen:
        config = cfg.telegram if row["channel"] == "telegram" else cfg.discord
        if not config.enabled:
            raise ValueError("Selected destination is disabled")
        available = {e["kind"] for e in row["events"]} & set(config.events)
        if not available.intersection(event_kinds):
            raise ValueError("No selected events for this destination")
        allowed.update(available)
    if set(event_kinds) - allowed:
        raise ValueError("Event was not offered or selected in settings")
    EnvFile().load_into_environ()
    for row in chosen:
        config = cfg.telegram if row["channel"] == "telegram" else cfg.discord
        selected = [
            e for e in row["events"] if e["kind"] in event_kinds and e["kind"] in config.events
        ]
        claimable = ["pending", "failed", "unknown", "unconfigured"] if retry else ["pending"]
        with get_session(db_path) as session:
            claimed = session.execute(
                update(NotificationDeliveryORM)
                .where(
                    NotificationDeliveryORM.id == row["id"],
                    NotificationDeliveryORM.status.in_(claimable),
                )
                .values(
                    status="sending",
                    detail="Delivery in progress; do not repeat",
                    selected_events_json=json.dumps([e["kind"] for e in selected]),
                )
            )
            if claimed.rowcount != 1:  # type: ignore[attr-defined]
                continue
        message = "DevSecOps-Agent\n" + "\n".join(e["message"] for e in selected)
        try:
            if row["channel"] == "telegram":
                result = send_telegram(
                    message, token_env=cfg.telegram.token_env, chat_env=cfg.telegram.chat_env
                )
            else:
                result = send_discord(message, webhook_env=cfg.discord.webhook_env)
        except Exception:  # noqa: BLE001 - isolate delivery from scan outcome
            # No raw exception text: a transport exception can contain a credential URL.
            result = DeliveryResult(
                "unknown", "Delivery was not acknowledged; acceptance is unknown"
            )
        with get_session(db_path) as session:
            saved = session.get(NotificationDeliveryORM, row["id"])
            assert saved is not None
            saved.status, saved.detail = result.status, result.detail
    receipt = deliveries(db_path, run_id)
    receipt["deliveries"] = [r for r in receipt["deliveries"] if r["channel"] in channels]
    return receipt


def notify_finished(db_path: str, run_id: int | str) -> dict[str, Any]:
    """Notification failure must never change scan outcome or discard evidence."""
    try:
        return offer_run(db_path, run_id)
    except Exception as exc:  # noqa: BLE001 - optional completion boundary
        logging.getLogger(__name__).warning(
            "Notification preparation failed (%s)", type(exc).__name__
        )
        return {
            "status": "failed",
            "detail": "Notification preparation failed; check settings",
            "deliveries": [],
        }


def handle(db_path: str, params: dict[str, Any]) -> dict[str, Any]:
    """Shared operator interface for CLI, local HTTP and the owned JSONL bridge."""
    action = params.get("action", "settings")
    if action in {"settings", "save"}:
        settings = save_settings(params["settings"]) if action == "save" else load_settings()
        return {"settings": settings.model_dump(), "events": EVENT_LABELS}
    run_id = params.get("run_id", "")
    if action == "complete":
        return notify_finished(db_path, run_id)
    if action == "deliveries":
        return deliveries(db_path, run_id)
    if action == "send":
        events, channels = params.get("events"), params.get("channels")
        if (
            not isinstance(events, list)
            or not isinstance(channels, list)
            or not all(isinstance(value, str) for value in [*events, *channels])
        ):
            raise ValueError("Choose event and destination lists")
        return send_selected(db_path, run_id, events, channels, retry=params.get("retry") is True)
    raise ValueError("Unknown notification action")
