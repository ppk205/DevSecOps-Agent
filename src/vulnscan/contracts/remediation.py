"""Limited remediation observations, separate from validation and finding status."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import model_validator

from ._base import VulnscanBaseModel


class FixVerification(VulnscanBaseModel):
    """Full-file baseline/patch rule comparison; human review remains required."""

    fixed: bool
    detail: str
    outcome: Literal["passed", "failed", "unavailable", "cancelled", "incomplete"]
    rule_id: str
    tool_version: str | None = None
    baseline_artifact: str | None = None
    patched_artifact: str | None = None
    baseline_sha256: str | None = None
    patched_sha256: str | None = None
    attempt_id: int | None = None

    @model_validator(mode="after")
    def consistent_outcome(self) -> Self:
        if self.fixed != (self.outcome == "passed"):
            raise ValueError("fixed must be true only for a passed verification")
        return self
