"""ProviderProfile và ProviderUsage — cấu hình và hạch toán Chat-Completions cho BYOK.

Các provider profile nằm trên đĩa (được mã hóa khi lưu trữ) và được chèn vào các
yêu cầu provider khi chạy. Các bản ghi sử dụng là dạng chỉ thêm (append-only) và điều
hành mức trần ngân sách 50 USD.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from ._base import VersionedModel
from .enums import ProviderProtocol


class ProviderProfile(VersionedModel):
    """Cấu hình được đặt tên cho một model provider BYOK đơn lẻ.

    ``id`` là một slug ổn định; ``label`` là bí danh dễ đọc hiển thị trên
    dashboard. ``api_key_env`` tham chiếu đến biến môi trường chứa khóa bí mật
    — khóa thực tế không bao giờ rời khỏi biến môi trường.
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
    """Bản ghi hạch toán dạng chỉ thêm (append-only) cho một lệnh gọi provider.

    Các bản ghi được ghi ngay sau khi mỗi yêu cầu hoàn tất (thành công hoặc
    thất bại) để việc kiểm tra ngân sách vẫn hoạt động ngay cả sau sự cố sập.
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
        """Tích lũy hai bản ghi sử dụng (giả định cùng provider/model)."""
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
