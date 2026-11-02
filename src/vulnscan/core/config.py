"""Versioned shared configuration (DR-10)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from vulnscan.contracts import ScanSpecification, ToolConfig, ToolName

PROFILES = {
    "fast": [ToolName.SEMGREP, ToolName.GITLEAKS],
    "full": [
        ToolName.SEMGREP,
        ToolName.GITLEAKS,
        ToolName.SPOTBUGS,
        ToolName.OWASP_DEPENDENCY_CHECK,
    ],
}


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    profile: Literal["fast", "full"] = "fast"
    fail_on: Literal["critical", "high", "medium", "low", "info", "none"] = "high"
    output_dir: str = "artifacts"
    timezone: str = "Asia/Saigon"
    timeout: int = Field(default=600, ge=1, le=86400)
    max_files: int = Field(default=100000, ge=1)
    allow_dirty: bool = False
    ci: bool = False
    laya: bool = True
    laya_config_path: str | None = None
    ai_review: bool = False
    provider_profile: str | None = None
    provider_model: str | None = None
    ai_report: bool = False
    allow_cloud_model: bool = False
    max_ai_findings: int = Field(default=10, ge=1, le=500)
    mode: Literal["deterministic", "hunt"] = "deterministic"
    tools: list[str] | None = Field(
        default=None,
        description="Optional scanner subset override (ToolName values); defaults to profile set.",
    )

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("unknown display timezone") from exc
        return value

    def specification(self, checkout: str, commit: str, repo: str) -> ScanSpecification:
        if self.tools is None:
            selected = list(PROFILES[self.profile])
        else:
            selected = []
            for name in self.tools:
                try:
                    selected.append(ToolName(name))
                except ValueError as exc:
                    raise ValueError(f"Unknown scanner tool: {name}") from exc
        return ScanSpecification(
            target_repository_url=repo,
            target_commit_sha=commit,
            repository_checkout_path=checkout,
            tools=[ToolConfig(tool=t) for t in selected],
            max_wall_seconds=self.timeout,
            max_file_count=self.max_files,
            rules_packs_version="0.2.0",
            metadata={"configuration": self.model_dump()},
        )


def resolve_config(
    profile: str | None = None, config: str | None = None, **flags: Any
) -> ScanConfig:
    values: dict[str, Any] = ScanConfig().model_dump()
    if profile is not None:
        values["profile"] = profile
        if profile == "full":
            values["timeout"] = 3600
    if config:
        payload = json.loads(Path(config).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise ValueError("configuration must be an object with schema_version: 1")
        values.update(payload)
    values.update({k: v for k, v in flags.items() if v is not None})
    try:
        return ScanConfig.model_validate(values)
    except ValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in e["loc"]) for e in exc.errors())
        raise ValueError(f"Invalid scan configuration fields: {fields}") from None
