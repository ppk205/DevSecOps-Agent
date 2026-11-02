"""Provider profiles and the two transports that talk to model APIs.

A provider is declared once as a profile and routed by protocol to a
transport: Anthropic Messages, or OpenAI Chat Completions (used by OpenAI,
OpenRouter, DeepSeek, Ollama, LM Studio and custom endpoints). Keys are read
only from the environment variable named in the profile.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, cast

import httpx

from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.core.model_consent import is_local_base_url
from vulnscan.providers.credentials import CredentialError, load_api_key, redact, redact_value
from vulnscan.providers.profile_store import list_profiles

from .messages import Message, ProviderError, Reply, ToolCall, Transport, Usage

__all__ = [
    "BUILTIN_PROFILES",
    "PRICES",
    "AnthropicTransport",
    "ChatCompletionsTransport",
    "all_profiles",
    "is_local",
    "make_transport",
    "price",
]

_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_ANTHROPIC_VERSION = "2023-06-01"
_ANTHROPIC_MAX_TOKENS = 4096


def _builtin(
    profile_id: str,
    label: str,
    protocol: ProviderProtocol,
    base_url: str,
    api_key_env: str,
    default_model: str | None = None,
    local: bool = False,
) -> ProviderProfile:
    return ProviderProfile(
        id=profile_id,
        label=label,
        protocol=protocol,
        base_url=base_url,
        api_key_env=api_key_env,
        default_model=default_model,
        metadata={"local": True} if local else {},
    )


BUILTIN_PROFILES: dict[str, ProviderProfile] = {
    "anthropic": _builtin(
        "anthropic",
        "Anthropic",
        ProviderProtocol.ANTHROPIC_MESSAGES,
        "https://api.anthropic.com/v1",
        "ANTHROPIC_API_KEY",
        "claude-sonnet-5-5",
    ),
    "openai": _builtin(
        "openai",
        "OpenAI",
        ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
        "https://api.openai.com/v1",
        "OPENAI_API_KEY",
    ),
    "openrouter": _builtin(
        "openrouter",
        "OpenRouter",
        ProviderProtocol.OPENAI_COMPATIBLE,
        "https://openrouter.ai/api/v1",
        "OPENROUTER_API_KEY",
    ),
    "deepseek": _builtin(
        "deepseek",
        "DeepSeek",
        ProviderProtocol.OPENAI_COMPATIBLE,
        "https://api.deepseek.com",
        "DEEPSEEK_API_KEY",
        "deepseek-chat",
    ),
    "ollama": _builtin(
        "ollama",
        "Ollama",
        ProviderProtocol.OPENAI_COMPATIBLE,
        "http://127.0.0.1:11434/v1",
        "",
        local=True,
    ),
    "lmstudio": _builtin(
        "lmstudio",
        "LM Studio",
        ProviderProtocol.OPENAI_COMPATIBLE,
        "http://127.0.0.1:1234/v1",
        "",
        local=True,
    ),
}

# USD per million input/output tokens. Empty until a run records real prices.
PRICES: dict[str, tuple[float, float]] = {}


def all_profiles(base: Path | None = None) -> dict[str, ProviderProfile]:
    """Built-in profiles, overridden by ``<base>/*.json`` user profiles."""
    profiles = dict(BUILTIN_PROFILES)
    directory = base or Path(".providers")
    if directory.is_dir():
        for profile in list_profiles(directory):
            profiles[profile.id] = profile
    return profiles


def is_local(profile: ProviderProfile) -> bool:
    """True when the profile runs on this machine, so no code leaves it."""
    return is_local_base_url(profile.base_url)


def price(model: str, usage: Usage) -> float:
    """Cost of *usage* at the recorded price for *model* (0.0 when unknown)."""
    rates = PRICES.get(model)
    if rates is None:
        return 0.0
    input_rate, output_rate = rates
    return (usage.input_tokens * input_rate + usage.output_tokens * output_rate) / 1_000_000


def _usage_from_wire(raw: Any, latency_ms: int) -> Usage:
    if not isinstance(raw, dict):
        return Usage(latency_ms=latency_ms)
    return Usage(
        input_tokens=int(raw.get("prompt_tokens") or raw.get("input_tokens") or 0),
        output_tokens=int(raw.get("completion_tokens") or raw.get("output_tokens") or 0),
        latency_ms=latency_ms,
    )


class _HttpTransport:
    """Shared HTTP plumbing: headers, retries and error redaction."""

    def __init__(
        self,
        profile: ProviderProfile,
        model: str | None = None,
        http: httpx.Client | None = None,
    ) -> None:
        resolved = model or profile.default_model
        if not resolved:
            raise ProviderError(
                f"Provider '{profile.id}' has no default model; "
                "pass one with /model <provider> <model>"
            )
        self.profile = profile
        self.model: str = resolved
        self._owns_client = http is None
        self.http = http or httpx.Client(timeout=float(profile.timeout_seconds))

    def close(self) -> None:
        if self._owns_client:
            self.http.close()

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json", **self.profile.headers}
        if self.profile.api_key_env:
            try:
                headers["Authorization"] = f"Bearer {load_api_key(self.profile.api_key_env)}"
            except CredentialError as exc:
                if not is_local(self.profile):
                    raise ProviderError(
                        f"Model {self.profile.id}: key missing; set its key before starting."
                    ) from exc
        return headers

    def _post(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        payload = redact_value(payload)
        last_error = "no attempt was made"
        for attempt in range(self.profile.max_retries + 1):
            try:
                response = self.http.post(url, json=payload, headers=headers)
            except httpx.RequestError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt >= self.profile.max_retries:
                    break
                time.sleep(2**attempt)
                continue
            if response.status_code in _RETRY_STATUS and attempt < self.profile.max_retries:
                last_error = f"HTTP {response.status_code}"
                time.sleep(2**attempt)
                continue
            if response.status_code >= 400:
                raise ProviderError(
                    redact(f"HTTP {response.status_code} from {self.profile.id}: {response.text}")
                )
            try:
                decoded = response.json()
            except ValueError as exc:
                raise ProviderError(f"Invalid JSON from {self.profile.id}: {exc}") from exc
            raw: Any = redact_value(decoded)
            if not isinstance(raw, dict):
                raise ProviderError(f"Invalid response from {self.profile.id}: expected an object")
            return cast("dict[str, Any]", raw)
        raise ProviderError(redact(f"{self.profile.id} request failed: {last_error}"))

    def _reply(
        self, data: dict[str, Any], message: Message, stop_reason: str, started: float
    ) -> Reply:
        usage = _usage_from_wire(data.get("usage"), int((time.perf_counter() - started) * 1000))
        usage.cost_usd = price(self.model, usage)
        return Reply(
            message=message,
            usage=usage,
            model=str(data.get("model") or self.model),
            stop_reason=stop_reason,
        )


class ChatCompletionsTransport(_HttpTransport):
    """OpenAI-compatible ``/chat/completions`` transport.

    Non-streaming on purpose: the harness asks for whole replies and the
    streaming path belongs to the chat TUI.
    """

    # ponytail: non-streaming; add SSE with the chat TUI

    @staticmethod
    def to_wire(system: str, messages: list[Message]) -> list[dict[str, Any]]:
        wire: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for message in messages:
            if message.role == "tool":
                wire.append(
                    {
                        "role": "tool",
                        "tool_call_id": message.tool_call_id or "",
                        "content": message.content,
                    }
                )
                continue
            if message.tool_calls:
                wire.append(
                    {
                        "role": message.role,
                        "content": message.content,
                        "tool_calls": [
                            {
                                "id": call.id,
                                "type": "function",
                                "function": {
                                    "name": call.name,
                                    "arguments": json.dumps(call.arguments),
                                },
                            }
                            for call in message.tool_calls
                        ],
                    }
                )
                continue
            wire.append({"role": message.role, "content": message.content})
        return wire

    @staticmethod
    def from_wire(data: dict[str, Any]) -> tuple[Message, str]:
        raw_choices: Any = data.get("choices") or []
        choice: Any = raw_choices[0] if isinstance(raw_choices, list) and raw_choices else {}
        raw_message: Any = choice.get("message") if isinstance(choice, dict) else {}
        message = raw_message if isinstance(raw_message, dict) else {}
        calls: list[ToolCall] = []
        raw_calls: Any = message.get("tool_calls") or []
        for item in raw_calls if isinstance(raw_calls, list) else []:
            if not isinstance(item, dict):
                continue
            function = item.get("function")
            function = function if isinstance(function, dict) else {}
            raw_arguments = function.get("arguments")
            parsed: Any
            try:
                parsed = json.loads(raw_arguments) if raw_arguments else {}
            except (TypeError, ValueError):
                parsed = None
            arguments = (
                cast("dict[str, Any]", parsed)
                if isinstance(parsed, dict)
                else {"_unparsed": raw_arguments}
            )
            calls.append(
                ToolCall(
                    id=str(item.get("id") or ""),
                    name=str(function.get("name") or ""),
                    arguments=arguments,
                )
            )
        content = message.get("content")
        stop = choice.get("finish_reason") if isinstance(choice, dict) else None
        return Message("assistant", str(content or ""), calls), str(stop or "")

    def complete(self, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> Reply:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": self.to_wire(system, messages),
            "temperature": 0,
        }
        if tools:
            payload["tools"] = [{"type": "function", "function": tool} for tool in tools]
        url = f"{self.profile.base_url.rstrip('/')}/chat/completions"
        started = time.perf_counter()
        data = self._post(url, payload, self._headers())
        message, stop = self.from_wire(data)
        return self._reply(data, message, stop, started)


class AnthropicTransport(_HttpTransport):
    """Anthropic Messages API transport."""

    # ponytail: non-streaming and no prompt caching; both belong to the chat TUI

    @staticmethod
    def to_wire(messages: list[Message]) -> list[dict[str, Any]]:
        wire: list[dict[str, Any]] = []
        open_tool_group = False
        for message in messages:
            if message.role == "tool":
                block = {
                    "type": "tool_result",
                    "tool_use_id": message.tool_call_id or "",
                    "content": message.content,
                }
                if open_tool_group:
                    wire[-1]["content"].append(block)
                else:
                    wire.append({"role": "user", "content": [block]})
                    open_tool_group = True
                continue
            open_tool_group = False
            if message.role == "assistant":
                blocks: list[dict[str, Any]] = []
                if message.content:
                    blocks.append({"type": "text", "text": message.content})
                blocks.extend(
                    {
                        "type": "tool_use",
                        "id": call.id,
                        "name": call.name,
                        "input": call.arguments,
                    }
                    for call in message.tool_calls
                )
                wire.append({"role": "assistant", "content": blocks or message.content})
                continue
            wire.append({"role": message.role, "content": message.content})
        return wire

    @staticmethod
    def from_wire(data: dict[str, Any]) -> Message:
        texts: list[str] = []
        calls: list[ToolCall] = []
        raw_blocks: Any = data.get("content") or []
        for block in raw_blocks if isinstance(raw_blocks, list) else []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                texts.append(str(block.get("text") or ""))
            elif block.get("type") == "tool_use":
                arguments = block.get("input")
                calls.append(
                    ToolCall(
                        id=str(block.get("id") or ""),
                        name=str(block.get("name") or ""),
                        arguments=dict(arguments) if isinstance(arguments, dict) else {},
                    )
                )
        return Message("assistant", "".join(texts), calls)

    def _headers(self) -> dict[str, str]:
        headers = super()._headers()
        authorization = headers.pop("Authorization", None)
        if authorization is not None:
            headers["x-api-key"] = authorization.removeprefix("Bearer ")
        headers["anthropic-version"] = _ANTHROPIC_VERSION
        return headers

    def complete(self, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> Reply:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": _ANTHROPIC_MAX_TOKENS,
            "temperature": 0,
            "system": system,
            "messages": self.to_wire(messages),
        }
        if tools:
            payload["tools"] = [
                {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "input_schema": tool.get("parameters", {}),
                }
                for tool in tools
            ]
        url = f"{self.profile.base_url.rstrip('/')}/messages"
        started = time.perf_counter()
        data = self._post(url, payload, self._headers())
        return self._reply(
            data, AnthropicTransport.from_wire(data), str(data.get("stop_reason") or ""), started
        )


def make_transport(profile: ProviderProfile, model: str | None = None) -> Transport:
    """Build the transport for *profile*, or raise when it cannot work."""
    if profile.protocol is ProviderProtocol.ANTHROPIC_MESSAGES:
        return AnthropicTransport(profile, model)
    if profile.protocol is ProviderProtocol.OPENAI_RESPONSES:
        raise ProviderError(
            f"Provider '{profile.id}' uses the Responses API, which the harness does not "
            "implement; use an OpenAI-compatible Chat Completions endpoint"
        )
    return ChatCompletionsTransport(profile, model)
