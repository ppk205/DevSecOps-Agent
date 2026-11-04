"""Project notification rules contain environment references, never credentials."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class NotificationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    mode: Literal["manual", "automatic"] = "manual"
    telegram: TelegramSettings = Field(default_factory=TelegramSettings)
    discord: DiscordSettings = Field(default_factory=DiscordSettings)


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
