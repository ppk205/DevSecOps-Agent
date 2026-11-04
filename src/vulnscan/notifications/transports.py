"""Bounded outbound Telegram/Discord messages with explicit acknowledgements."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from vulnscan.core.security import sanitize
from vulnscan.providers.credentials import redact

_MESSAGE_LIMIT = 1800
_RESPONSE_LIMIT = 65536


@dataclass(frozen=True)
class DeliveryResult:
    status: Literal["sent", "failed", "unknown", "unconfigured"]
    detail: str
    http_status: int | None = None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> tuple[int, dict[str, Any]]:
    # urllib does not emit HTTPX's INFO-level request URL, which would contain
    # Telegram/Discord credentials. Exceptions and response bodies stay internal.
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "DevSecOps-Agent"},
    )
    opener = build_opener(_NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        status = int(response.status)
        body = response.read(_RESPONSE_LIMIT + 1)
    if len(body) > _RESPONSE_LIMIT:
        return status, {}
    try:
        parsed = json.loads(body) if body else {}
    except (ValueError, UnicodeError):
        parsed = {}
    return status, parsed if isinstance(parsed, dict) else {}


def _message(text: str, *secrets: str) -> str:
    safe = str(sanitize(redact(text)))
    for value in secrets:
        if value:
            safe = safe.replace(value, "[REDACTED]")
    return safe[:_MESSAGE_LIMIT]


def _network_failure() -> DeliveryResult:
    return DeliveryResult("unknown", "Delivery was not acknowledged; remote acceptance is unknown")


def send_telegram(
    text: str,
    *,
    token_env: str = "DEVSEC_TELEGRAM_BOT_TOKEN",
    chat_env: str = "DEVSEC_TELEGRAM_CHAT_ID",
    timeout: float = 5.0,
) -> DeliveryResult:
    token = os.environ.get(token_env, "").strip()
    chat_id = os.environ.get(chat_env, "").strip()
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token) or not chat_id:
        return DeliveryResult("unconfigured", "Telegram bot token or chat ID is missing or invalid")
    payload = {
        "chat_id": chat_id,
        "text": _message(text, token),
        "link_preview_options": {"is_disabled": True},
    }
    try:
        status, data = _post_json(
            f"https://api.telegram.org/bot{token}/sendMessage", payload, timeout
        )
    except (OSError, URLError, ValueError):
        return _network_failure()
    if 200 <= status < 300 and data.get("ok") is True:
        result = data.get("result")
        if (
            isinstance(result, dict)
            and type(result.get("message_id")) is int
            and result["message_id"] > 0
        ):
            return DeliveryResult("sent", "Telegram acknowledged the message", status)
        return DeliveryResult(
            "unknown", "Telegram did not return a message acknowledgement", status
        )
    code = data.get("error_code", status)
    return DeliveryResult(
        "failed",
        f"Telegram rejected delivery (status {code if type(code) is int else status})",
        status,
    )


def send_discord(
    text: str,
    *,
    webhook_env: str = "DEVSEC_DISCORD_WEBHOOK_SECRET",
    timeout: float = 5.0,
) -> DeliveryResult:
    secret = os.environ.get(webhook_env, "").strip()
    try:
        url = urlsplit(secret)
        if (
            url.scheme != "https"
            or url.hostname not in {"discord.com", "discordapp.com"}
            or url.username
            or url.password
            or url.port not in {None, 443}
            or url.fragment
            or not re.fullmatch(r"/api/(?:v[0-9]+/)?webhooks/[0-9]+/[A-Za-z0-9._-]+/?", url.path)
        ):
            raise ValueError("invalid webhook")
        query = dict(parse_qsl(url.query, keep_blank_values=True))
        if set(query) - {"thread_id", "wait"} or (
            query.get("thread_id") and not query["thread_id"].isdigit()
        ):
            raise ValueError("invalid webhook parameters")
        query["wait"] = "true"
        endpoint = urlunsplit((url.scheme, url.netloc, url.path, urlencode(query), ""))
    except ValueError:
        return DeliveryResult("unconfigured", "Discord requires a valid HTTPS Discord webhook URL")
    token = url.path.rstrip("/").split("/")[-1]
    payload = {"content": _message(text, secret, token), "allowed_mentions": {"parse": []}}
    try:
        status, data = _post_json(endpoint, payload, timeout)
    except (OSError, URLError, ValueError):
        return _network_failure()
    if 200 <= status < 300 and isinstance(data.get("id"), str) and data["id"]:
        return DeliveryResult("sent", "Discord acknowledged the message", status)
    if 200 <= status < 300:
        return DeliveryResult("unknown", "Discord did not return a message acknowledgement", status)
    return DeliveryResult("failed", f"Discord rejected delivery (HTTP {status})", status)
