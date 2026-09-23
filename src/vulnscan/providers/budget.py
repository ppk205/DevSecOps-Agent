"""Budget enforcement for AI usage — USD 50 total ceiling.

Tracks per-provider and aggregate spend from :class:`ProviderUsage` records.
Provider failure or budget exhaustion preserves baseline scanner findings
and produces an unresolved AI assessment.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from vulnscan.contracts.enums import ToolName
from vulnscan.contracts.provider import ProviderUsage


class BudgetExhausted(Exception):
    """Raised when the next request would exceed the remaining budget."""


class BudgetManager:
    """Thread-safe budget tracker.

    Parameters
    ----------
    total_usd:
        Hard ceiling for total AI spend (default: 50.0 per project plan).
    reserve_usd:
        Minimum amount always reserved for reruns.  Requests that would
        push spend past *total_usd - reserve_usd* are rejected.
    """

    def __init__(self, total_usd: float = 50.0, reserve_usd: float = 10.0) -> None:
        self._total = total_usd
        self._reserve = reserve_usd
        self._spent: dict[str, float] = {}  # provider_id -> USD
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    @property
    def total_budget(self) -> float:
        return self._total

    @property
    def available(self) -> float:
        with self._lock:
            return self._total - sum(self._spent.values())

    @property
    def spent(self) -> float:
        with self._lock:
            return sum(self._spent.values())

    def spent_by_provider(self, provider_id: str) -> float:
        with self._lock:
            return self._spent.get(provider_id, 0.0)

    # ------------------------------------------------------------------
    # Mutators
    # ------------------------------------------------------------------
    def check(self, estimated_cost: float = 0.0) -> None:
        """Raise :class:`BudgetExhausted` if *estimated_cost* exceeds headroom."""
        with self._lock:
            remaining = self._total - sum(self._spent.values())
            if estimated_cost > remaining - self._reserve:
                raise BudgetExhausted(
                    f"Estimated cost ${estimated_cost:.4f} exceeds remaining "
                    f"budget ${remaining - self._reserve:.4f} (total=${self._total}, "
                    f"spent=${sum(self._spent.values()):.4f}, reserve=${self._reserve})"
                )

    def record(self, usage: ProviderUsage) -> None:
        """Record a completed usage entry and update the provider total."""
        cost = usage.cost_usd or 0.0
        with self._lock:
            self._spent[usage.provider_id] = self._spent.get(usage.provider_id, 0.0) + cost

    def summary(self) -> dict[str, float]:
        """Return a snapshot of per-provider and total spend."""
        with self._lock:
            return {
                "total_budget": self._total,
                "total_spent": sum(self._spent.values()),
                "available": self._total - sum(self._spent.values()),
                **{f"spent_{k}": v for k, v in self._spent.items()},
            }
