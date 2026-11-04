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
from .credentials import load_api_key, redact
from .events import emit_model_event


def _message_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(str(part.get("text", "")) for part in value if isinstance(part, dict))
    return ""


def _redact_data(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        text = redact(value)
        return text.replace(secret, "[REDACTED]") if secret else text
    if isinstance(value, dict):
        return {key: _redact_data(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_data(item, secret) for item in value]
    return value


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
    reasoning: str = ""


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

        wire_messages = []
        for message in messages:
            wire: dict[str, Any] = {"role": message.role, "content": message.content}
            if message.tool_calls:
                wire["tool_calls"] = message.tool_calls
            if message.tool_call_id:
                wire["tool_call_id"] = message.tool_call_id
            wire_messages.append(wire)
        payload: dict[str, Any] = {
            "model": use_model,
            "messages": wire_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        api_key = self._get_key()
        payload = _redact_data(payload, api_key)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        for key, value in (self.profile.headers or {}).items():
            if key.lower() in ("authorization", "content-type"):
                continue
            headers[key] = value

        url = f"{self.profile.base_url.rstrip('/')}/chat/completions"

        resp = None
        attempts = max(1, self.profile.max_retries + 1)
        for attempt in range(attempts):
            emit_model_event(
                "call",
                "running",
                f"Calling {self.profile.id} / {use_model} (attempt {attempt + 1})",
                provider=self.profile.id,
                model=use_model,
            )
            try:
                with httpx.Client(timeout=self.profile.timeout_seconds) as client:
                    resp = client.post(url, json=payload, headers=headers)
                    resp.raise_for_status()
                break
            except httpx.HTTPStatusError as exc:
                emit_model_event(
                    "call",
                    "failed",
                    f"Provider {self.profile.id} returned HTTP {exc.response.status_code}",
                    provider=self.profile.id,
                    model=use_model,
                    usage={},
                )
                if exc.response.status_code == 429 and attempt < attempts - 1:
                    import time as _time

                    retry_after = exc.response.headers.get("retry-after")
                    try:
                        wait = float(retry_after) if retry_after else 20.0 * (attempt + 1)
                    except (TypeError, ValueError):
                        wait = 20.0 * (attempt + 1)
                    _time.sleep(min(wait, 120.0))
                    continue
                raise ProviderError(
                    _redact_data(
                        f"HTTP {exc.response.status_code} from {self.profile.id}: {exc.response.text[:500]}",
                        api_key,
                    )
                ) from exc
            except httpx.RequestError as exc:
                emit_model_event(
                    "call",
                    "failed",
                    f"Provider request failed: {type(exc).__name__}",
                    provider=self.profile.id,
                    model=use_model,
                    usage={},
                )
                raise ProviderError(
                    _redact_data(f"Request failed for {self.profile.id}: {exc}", api_key)
                ) from exc
            except (OSError, ValueError, TypeError) as exc:
                emit_model_event(
                    "call",
                    "failed",
                    f"Provider transport could not start: {type(exc).__name__}",
                    provider=self.profile.id,
                    model=use_model,
                    usage={},
                )
                raise ProviderError("Provider transport could not start") from exc
        assert resp is not None

        try:
            data = _redact_data(resp.json(), api_key)
            choice = data.get("choices", [{}])[0]
            message = choice.get("message", {})
            reasoning = _message_text(message.get("reasoning_content") or message.get("reasoning"))
            content = _message_text(message.get("content")) or reasoning
        except (ValueError, TypeError, AttributeError, IndexError) as exc:
            emit_model_event(
                "call",
                "failed",
                "Provider returned an invalid response",
                provider=self.profile.id,
                model=use_model,
                usage={},
            )
            raise ProviderError("Provider returned an invalid response") from exc

        # Parse response (some reasoning gateways put the answer in
        # `reasoning_content`/`reasoning` and leave `content` empty).
        chat_resp = ChatResponse(
            content=content if isinstance(content, str) else "",
            tool_calls=message.get("tool_calls") or [],
            usage=data.get("usage") or {},
            model=data.get("model") or use_model,
            finish_reason=choice.get("finish_reason", ""),
            raw=data,
            reasoning=reasoning,
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

        # ponytail: call-level progress, not a token-by-token provider stream.
        explanation = reasoning or chat_resp.content
        text = f"Response from {self.profile.id} / {chat_resp.model}"
        if explanation:
            text += "\nReturned explanation/response:\n" + explanation[:8000]
        requested = [
            str(call.get("function", {}).get("name", "unknown"))
            for call in chat_resp.tool_calls
            if isinstance(call, dict)
        ]
        if requested:
            text += "\nRequested tools: " + ", ".join(requested)
        emit_model_event(
            "call",
            "completed",
            text,
            provider=self.profile.id,
            model=chat_resp.model,
            usage=chat_resp.usage,
        )
        return chat_resp


class ProviderError(Exception):
    """Provider-level HTTP or response error."""
