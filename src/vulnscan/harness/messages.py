"""Provider-neutral message format used by the harness session loop.

One internal format is converted to each provider's wire format at the
transport edge, so sessions, gates, telemetry and the user interface never
depend on a vendor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from vulnscan.contracts.provider import ProviderProfile


@dataclass
class ToolCall:
    """One model-requested tool invocation."""

    id: str
    name: str
    arguments: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "arguments": dict(self.arguments)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolCall:
        arguments = data.get("arguments")
        return cls(
            id=str(data.get("id") or ""),
            name=str(data.get("name") or ""),
            arguments=dict(arguments) if isinstance(arguments, dict) else {},
        )


@dataclass
class Message:
    """One turn of the internal conversation history."""

    role: str
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "tool_calls": [call.to_dict() for call in self.tool_calls],
            "tool_call_id": self.tool_call_id,
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Message:
        raw_calls = data.get("tool_calls")
        tool_call_id = data.get("tool_call_id")
        name = data.get("name")
        return cls(
            role=str(data.get("role") or ""),
            content=str(data.get("content") or ""),
            tool_calls=[ToolCall.from_dict(call) for call in raw_calls if isinstance(call, dict)]
            if isinstance(raw_calls, list)
            else [],
            tool_call_id=str(tool_call_id) if tool_call_id is not None else None,
            name=str(name) if name is not None else None,
        )


@dataclass
class Usage:
    """Token and cost accounting for one provider call."""

    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0


@dataclass
class Reply:
    """One model reply: the message plus what it cost."""

    message: Message
    usage: Usage
    model: str
    stop_reason: str = ""


class ProviderError(Exception):
    """Raised when a provider call cannot produce a usable reply."""


class Transport(Protocol):
    """One provider transport, chosen by profile protocol."""

    profile: ProviderProfile
    model: str

    def complete(
        self, system: str, messages: list[Message], tools: list[dict[str, Any]]
    ) -> Reply: ...


__all__ = ["Message", "ProviderError", "Reply", "ToolCall", "Transport", "Usage"]
