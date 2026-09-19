"""ProviderProfile and ProviderUsage — BYOK Chat-Completions configuration and accounting.

Provider profiles live on disk (encrypted at rest) and are injected into
provider requests at run time.  Usage records are append-only and drive the
USD 50 budget ceiling.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import ProviderProtocol


class ProviderProfile(VersionedModel):
    """Named configuration for a single BYOK model provider.

    The ``id`` is a stable slug; ``label`` is a human-readable alias shown on
    the dashboard.  ``api_key_env`` references an environment variable holding
    the secret — the actual key never leaves the env.
    """

    id: str = Field(
        ...,
        description="Stable provider slug, e.g. 'openai-main'.",
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    label: str = Field(
        ...,
        description="Human-readable name shown in the dashboard.",
    )
    protocol: ProviderProtocol = Field(
        ...,
        description="Wire protocol used to talk to the provider.",
    )
    base_url: str = Field(
        ...,
        description="API endpoint URL, e.g. 'https://api.openai.com/v1'.",
    )
    api_key_env: str = Field(
        ...,
        description="Name of the environment variable that holds the API key.",
    )
    models: list[str] = Field(
        default_factory=list,
        description="Model identifiers this provider can serve, e.g. ['gpt-4o', 'gpt-4o-mini'].",
    )
    default_model: str | None = Field(
        default=None,
        description="Model used when the scan spec does not name one.",
    )
    timeout_seconds: int = Field(
        default=120,
        description="Per-request timeout in seconds.",
        ge=1,
    )
    max_retries: int = Field(
        default=3,
        description="Exponential-backoff retry limit per request.",
        ge=0,
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Extra HTTP headers (non-secret).  Authorization is managed internally.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form provider metadata for UI display.",
    )

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key_env)


class ProviderUsage(VersionedModel):
    """Append-only accounting record for one provider call.

    Records are written immediately after each request completes (success or
    failure) so budget checks work even after a crash.
    """

    provider_id: str = Field(
        ...,
        description="Provider slug matching a ProviderProfile.id.",
    )
    model: str = Field(
        ...,
        description="Model identifier used for this call.",
    )
    timestamp: datetime = Field(
        ...,
        description="UTC timestamp of the call completion.",
    )
    prompt_tokens: int = Field(
        default=0,
        description="Number of tokens in the prompt.",
        ge=0,
    )
    completion_tokens: int = Field(
        default=0,
        description="Number of tokens in the completion.",
        ge=0,
    )
    total_tokens: int = Field(
        default=0,
        description="prompt_tokens + completion_tokens.",
        ge=0,
    )
    cost_usd: float = Field(
        default=0.0,
        description="Estimated cost in USD.",
        ge=0.0,
    )
    latency_ms: int = Field(
        default=0,
        description="Wall-clock latency in milliseconds.",
        ge=0,
    )
    succeeded: bool = Field(
        ...,
        description="True if the request returned a usable response.",
    )
    error: str | None = Field(
        default=None,
        description="Error message if the request failed.",
    )
    run_id: str | None = Field(
        default=None,
        description="RunManifest.run_id this call belongs to.",
    )
    stage: str | None = Field(
        default=None,
        description="Pipeline stage that triggered the call, e.g. 'assess'.",
    )
    request_id: str | None = Field(
        default=None,
        description="Provider-returned request ID for debugging.",
    )

    def __add__(self, other: ProviderUsage) -> ProviderUsage:
        """Accumulate two usage records (same provider/model assumed)."""
        if self.provider_id != other.provider_id or self.model != other.model:
            raise ValueError("Cannot accumulate usage for different provider/model pairs.")
        return ProviderUsage(
            provider_id=self.provider_id,
            model=self.model,
            timestamp=other.timestamp,
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
            cost_usd=self.cost_usd + other.cost_usd,
            latency_ms=self.latency_ms + other.latency_ms,
            succeeded=self.succeeded and other.succeeded,
            error=other.error,
            run_id=other.run_id,
            stage=other.stage,
            request_id=other.request_id,
        )


__all__ = ["ProviderProfile", "ProviderUsage"]
