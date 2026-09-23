"""T04 gate: budget enforcement — USD 50 ceiling, per-provider tracking."""

from datetime import datetime, timezone

from vulnscan.contracts.enums import ToolName
from vulnscan.contracts.provider import ProviderUsage
from vulnscan.providers.budget import BudgetManager, BudgetExhausted


class TestBudgetManager:
    def test_initial_budget(self):
        bm = BudgetManager(total_usd=50.0, reserve_usd=10.0)
        assert bm.total_budget == 50.0
        assert bm.available == 50.0
        assert bm.spent == 0.0

    def test_record_usage(self):
        bm = BudgetManager(total_usd=50.0)
        usage = ProviderUsage(
            provider_id="test-provider",
            model="gpt-4o",
            timestamp=datetime.now(timezone.utc),
            prompt_tokens=1000,
            completion_tokens=500,
            total_tokens=1500,
            cost_usd=5.0,
            succeeded=True,
        )
        bm.record(usage)
        assert bm.spent == 5.0
        assert bm.available == 45.0
        assert bm.spent_by_provider("test-provider") == 5.0

    def test_budget_exhausted(self):
        bm = BudgetManager(total_usd=10.0, reserve_usd=5.0)
        # available = 5.0 (after reserve)
        with pytest.raises(BudgetExhausted):
            bm.check(estimated_cost=6.0)
        # Should succeed within reserve
        bm.check(estimated_cost=5.0)

    def test_summary(self):
        bm = BudgetManager(total_usd=50.0)
        usage = ProviderUsage(
            provider_id="p1",
            model="gpt-4o",
            timestamp=datetime.now(timezone.utc),
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
            cost_usd=1.5,
            succeeded=True,
        )
        bm.record(usage)
        summary = bm.summary()
        assert summary["total_budget"] == 50.0
        assert summary["total_spent"] == 1.5
        assert summary["available"] == 48.5
        assert summary["spent_p1"] == 1.5


import pytest  # noqa: E402
