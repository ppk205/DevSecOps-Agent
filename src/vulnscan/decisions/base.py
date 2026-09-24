"""Protocol for optional local decision backends."""

from __future__ import annotations

from typing import Protocol

from vulnscan.contracts.decision import DecisionRequest, DecisionResult


class DecisionBackend(Protocol):
    """Small typed-decision interface; deliberately not a chat provider."""

    def predict(self, request: DecisionRequest) -> DecisionResult:
        """Return a structured advisory decision without raising for model failure."""
