"""Project notification rules contain environment references, never credentials."""

from __future__ import annotations

import json
import os
import re
import tempfile
import unicodedata
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnscan.infra.envfile import find_project_root

from .events import NotificationKind


class _Channel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    events: list[NotificationKind] = Field(default_factory=list)

    @field_validator("events")
    @classmethod
    def unique_events(cls, value: list[NotificationKind]) -> list[NotificationKind]:
        return list(dict.fromkeys(value))


class TelegramSettings(_Channel):
    token_env: str = "DEVSEC_TELEGRAM_BOT_TOKEN"
    chat_env: str = "DEVSEC_TELEGRAM_CHAT_ID"

    @field_validator("token_env", "chat_env")
    @classmethod
    def environment_reference(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("use an environment variable name")
        return value


class DiscordSettings(_Channel):
    webhook_env: str = "DEVSEC_DISCORD_WEBHOOK_SECRET"

    @field_validator("webhook_env")
    @classmethod
    def environment_reference(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("use an environment variable name")
        return value


class WebhookSettings(_Channel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    url_env: str = "DEVSEC_WEBHOOK_URL"
    signing_key_env: str = "DEVSEC_WEBHOOK_SIGNING_SECRET"
    allowed_hosts: list[str] = Field(default_factory=list)

    @field_validator("url_env", "signing_key_env")
    @classmethod
    def environment_reference(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("use an environment variable name")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def exact_hosts(cls, values: list[str]) -> list[str]:
        hosts: list[str] = []
        for value in values:
            if any(c.isspace() or unicodedata.category(c).startswith("C") for c in value):
                raise ValueError("use exact DNS hostnames")
            try:
                host = value.encode("idna").decode("ascii").lower().rstrip(".")
                # ASCII A-labels must also represent valid IDNA names.
                host.encode("ascii").decode("idna")
            except UnicodeError:
                raise ValueError("use exact DNS hostnames") from None
            if (
                not host
                or len(host) > 253
                or any(
                    not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in host.split(".")
                )
            ):
                raise ValueError("use exact DNS hostnames")
            try:
                ip_address(host)
            except ValueError:
                hosts.append(host)
            else:
                raise ValueError("use exact DNS hostnames")
        return list(dict.fromkeys(hosts))

    @model_validator(mode="after")
    def enabled_requires_host(self) -> Self:
        if self.enabled and not self.allowed_hosts:
            raise ValueError("enabled webhook requires an exact hostname")
        return self


class NotificationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    schema_version: Literal[2] = 2
    mode: Literal["manual", "automatic"] = "manual"
    telegram: TelegramSettings = Field(default_factory=TelegramSettings)
    discord: DiscordSettings = Field(default_factory=DiscordSettings)
    webhook: WebhookSettings = Field(default_factory=WebhookSettings)

    @model_validator(mode="before")
    @classmethod
    def normalize_version(cls, values: Any) -> Any:
        if isinstance(values, dict):
            version = values.get("schema_version", 2)
            if type(version) is not int or version not in {1, 2}:
                raise ValueError("unsupported notification settings version")
            values = {**values, "schema_version": 2}
            if version == 1:
                values["webhook"] = {}  # A v1 document cannot opt in to a new channel.
        return values


def settings_path(base: Path | None = None) -> Path:
    return (base if base is not None else find_project_root()) / ".devsec-notifications.json"


def load_settings(*, base: Path | None = None) -> NotificationSettings:
    path = settings_path(base)
    if not path.is_file():
        return NotificationSettings()
    try:
        return NotificationSettings.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("Invalid notification settings") from None


def save_settings(
    values: NotificationSettings | dict[str, Any], *, base: Path | None = None
) -> NotificationSettings:
    try:
        if isinstance(values, NotificationSettings):
            values = values.model_dump()
        settings = NotificationSettings.model_validate(values)
    except ValueError:
        # Validation errors can echo an accidentally pasted webhook URL.
        raise ValueError("Invalid notification settings") from None
    path = settings_path(base)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as file:
            temporary = Path(file.name)
            json.dump(settings.model_dump(), file, indent=2)
            file.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return settings
