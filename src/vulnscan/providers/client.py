"""Chat Completions HTTP client — provider-agnostic, BYOK.

Supports any OpenAI-compatible ``/chat/completions`` endpoint (OpenAI,
OpenRouter, OpenCode Zen, etc.).  Wire protocol is plain HTTP; no SDK
dependency.  Keys never leave the process; they are passed via
``Authorization: Bearer <key>`` headers only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from vulnscan.contracts.provider import ProviderProfile, ProviderUsage

from .budget import BudgetManager
from .credentials import load_api_key


@dataclass
class ChatMessage:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


@dataclass
class ChatResponse:
    """Parsed response from /chat/completions."""

    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    model: str = ""
    finish_reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class ProviderClient:
    """Stateless Chat Completions client with budget enforcement.

    Parameters
    ----------
    profile:
        Provider configuration (endpoint, model, timeout, etc.)
    budget:
        Shared budget tracker.  If ``None``, no budget checks are performed.
    """

    def __init__(
        self,
        profile: ProviderProfile,
        budget: BudgetManager | None = None,
    ) -> None:
        self.profile = profile
        self.budget = budget
        self._key: str | None = None

    def _get_key(self) -> str:
        if self._key is None:
            self._key = load_api_key(self.profile.api_key_env)
        return self._key

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
    ) -> ChatResponse:
        """Send a chat completion request.

        Raises
        ------
        BudgetExhausted
            If the request would exceed the budget ceiling.
        ProviderError
            On HTTP or response-level errors.
        """
        use_model = (
            model
            or self.profile.default_model
            or (self.profile.models[0] if self.profile.models else None)
        )
        if not use_model:
            raise ValueError("No model specified and profile has no default_model or models.")

        # Budget pre-check
        if self.budget:
            self.budget.check()

        payload: dict[str, Any] = {
            "model": use_model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        headers = {
            "Authorization": f"Bearer {self._get_key()}",
            "Content-Type": "application/json",
        }

        url = f"{self.profile.base_url.rstrip('/')}/chat/completions"

        try:
            with httpx.Client(timeout=self.profile.timeout_seconds) as client:
                resp = client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProviderError(
                f"HTTP {exc.response.status_code} from {self.profile.id}: {exc.response.text[:500]}"
            ) from exc
        except httpx.RequestError as exc:
            raise ProviderError(f"Request failed for {self.profile.id}: {exc}") from exc

        data = resp.json()

        # Parse response
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})

        chat_resp = ChatResponse(
            content=message.get("content") or "",
            tool_calls=message.get("tool_calls") or [],
            usage=data.get("usage", {}),
            model=data.get("model", use_model),
            finish_reason=choice.get("finish_reason", ""),
            raw=data,
        )

        # Record usage
        if self.budget and chat_resp.usage:
            input_tokens = chat_resp.usage.get("prompt_tokens", 0)
            output_tokens = chat_resp.usage.get("completion_tokens", 0)
            total_tokens = chat_resp.usage.get("total_tokens", input_tokens + output_tokens)
            usage = ProviderUsage(
                provider_id=self.profile.id,
                model=use_model,
                timestamp=datetime.now(UTC),
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                total_tokens=total_tokens,
                cost_usd=0.0,
                succeeded=True,
                run_id="",
            )
            self.budget.record(usage)

        return chat_resp


class ProviderError(Exception):
    """Provider-level HTTP or response error."""
