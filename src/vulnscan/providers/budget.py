"""Thực thi ngân sách cho việc sử dụng AI — trần tối đa 50 USD.

Theo dõi chi tiêu theo từng nhà cung cấp và tổng chi tiêu từ các bản ghi :class:`ProviderUsage`.
Khi nhà cung cấp gặp sự cố hoặc cạn kiệt ngân sách, các finding từ scanner cơ sở vẫn được bảo toàn
và tạo ra một assessment AI chưa phân giải.
"""

from __future__ import annotations

import threading

from vulnscan.contracts.provider import ProviderUsage


class BudgetExhausted(Exception):
    """Ném ra khi yêu cầu tiếp theo sẽ vượt quá ngân sách còn lại."""


class BudgetManager:
    """Bộ theo dõi ngân sách an toàn đa luồng (thread-safe).

    Parameters
    ----------
    total_usd:
        Mức trần cứng cho tổng chi tiêu AI (mặc định: 50.0 theo kế hoạch dự án).
    reserve_usd:
        Số tiền tối thiểu luôn được dự trữ cho các lượt chạy lại. Các yêu cầu
        làm chi tiêu vượt quá *total_usd - reserve_usd* sẽ bị từ chối.
    """

    def __init__(
        self,
        total_usd: float = 50.0,
        reserve_usd: float = 10.0,
        *,
        max_requests: int | None = None,
    ) -> None:
        if max_requests is not None and max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        self._total = total_usd
        self._reserve = reserve_usd
        self._max_requests = max_requests
        self._attempts = 0
        self._spent: dict[str, float] = {}  # provider_id -> USD
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Truy vấn
    # ------------------------------------------------------------------
    @property
    def total_budget(self) -> float:
        return self._total

    @property
    def max_requests(self) -> int | None:
        return self._max_requests

    @property
    def attempts(self) -> int:
        with self._lock:
            return self._attempts

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
    # Các phương thức biến đổi (Mutators)
    # ------------------------------------------------------------------
    def check(self, estimated_cost: float = 0.0) -> None:
        """Ném :class:`BudgetExhausted` nếu *estimated_cost* vượt quá ngân sách khả dụng."""
        with self._lock:
            remaining = self._total - sum(self._spent.values())
            if estimated_cost > remaining - self._reserve:
                raise BudgetExhausted(
                    f"Estimated cost ${estimated_cost:.4f} exceeds remaining "
                    f"budget ${remaining - self._reserve:.4f} (total=${self._total}, "
                    f"spent=${sum(self._spent.values()):.4f}, reserve=${self._reserve})"
                )

    def reserve_request(self) -> None:
        """Count one provider POST attempt independently of monetary usage."""
        with self._lock:
            if self._max_requests is not None and self._attempts >= self._max_requests:
                raise BudgetExhausted(f"Model request limit reached ({self._attempts} attempts)")
            self._attempts += 1

    def release_request(self) -> None:
        """Release a reservation when its POST has yet to start."""
        with self._lock:
            self._attempts -= 1

    def record(self, usage: ProviderUsage) -> None:
        """Ghi lại mục sử dụng đã hoàn thành và cập nhật tổng chi tiêu của provider."""
        cost = usage.cost_usd or 0.0
        with self._lock:
            self._spent[usage.provider_id] = self._spent.get(usage.provider_id, 0.0) + cost

    def summary(self) -> dict[str, float]:
        """Trả về một snapshot chi tiêu theo từng provider và tổng chi tiêu."""
        with self._lock:
            return {
                "total_budget": self._total,
                "total_spent": sum(self._spent.values()),
                "available": self._total - sum(self._spent.values()),
                **{f"spent_{k}": v for k, v in self._spent.items()},
            }
