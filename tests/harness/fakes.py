"""Test doubles shared by the harness tests."""

from __future__ import annotations

from typing import Any

from vulnscan.contracts.provider import ProviderProfile
from vulnscan.harness.messages import Message, Reply, Transport
from vulnscan.harness.providers import BUILTIN_PROFILES


class BatchAgent:
    """A raw Laya agent double that answers every batch with one route."""

    def __init__(self, route: str = "fast_verification") -> None:
        self.route = route
        self.batch_calls: list[list[dict[str, Any]]] = []
        self.single_calls = 0

    def predict_batch(
        self, states: list[dict[str, Any]], questions: dict[str, Any], **kwargs: Any
    ) -> list[dict[str, Any]]:
        self.batch_calls.append(list(states))
        return [{"answers": _answers(self.route)} for _ in states]

    def predict(
        self, state: dict[str, Any], questions: dict[str, Any], **kwargs: Any
    ) -> dict[str, Any]:
        self.single_calls += 1
        return {"answers": _answers(self.route)}


def _answers(route: str) -> dict[str, Any]:
    return {
        "recommended_action": {
            "type": "choice",
            "choice": route,
            "probabilities": {route: 0.88, "human_review": 0.12},
            "confidence": 0.88,
        },
        "evidence_sufficiency": {
            "type": "score",
            "score": 1.0,
            "probabilities": {"0": 0.2, "1": 0.6, "2": 0.2},
            "confidence": 0.6,
        },
        "needs_human_review": {"type": "noul", "noul": 0.1, "confidence": 0.9},
    }


class ScriptedTransport(Transport):
    """A transport that replays prepared replies and records its prompts."""

    def __init__(
        self,
        replies: list[Reply | Exception],
        profile: ProviderProfile = BUILTIN_PROFILES["ollama"],
        model: str = "fake",
    ) -> None:
        self.replies = list(replies)
        self.profile = profile
        self.model = model
        self.calls: list[list[Message]] = []

    def complete(self, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> Reply:
        self.calls.append(list(messages))
        if not self.replies:
            raise AssertionError("ScriptedTransport ran out of replies")
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


__all__ = ["BatchAgent", "ScriptedTransport", "_answers"]
