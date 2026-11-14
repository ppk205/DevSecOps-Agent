"""Stage tracker — lưu giữ các chuyển đổi giai đoạn để lịch sử vẫn tồn tại sau khi khởi động lại.

Một lần chạy bị phân tích một phần hoặc thất bại không bao giờ được trông như sạch: một giai
đoạn không đạt tới COMPLETED sẽ được báo cáo là PARTIAL (nếu nó tạo ra đầu ra) hoặc FAILED.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from ..storage.models import StageORM


def _utcnow() -> datetime:
    return datetime.now(UTC)


class StageTracker:
    """Ghi lại vòng đời giai đoạn đối với lần chạy được lưu trong DB."""

    def __init__(self, session: Session, run_id: int) -> None:
        self.session = session
        self.run_id = run_id

    def _next_ordinal(self) -> int:
        last = (
            self.session.query(StageORM)
            .filter(StageORM.run_id == self.run_id)
            .order_by(StageORM.ordinal.desc())
            .first()
        )
        return (last.ordinal + 1) if last else 0

    def start(self, name: str) -> StageORM:
        st = StageORM(
            run_id=self.run_id,
            ordinal=self._next_ordinal(),
            name=name,
            status="running",
            started_at=_utcnow(),
        )
        self.session.add(st)
        self.session.flush()
        return st

    def complete(self, stage_id: int) -> None:
        st = self.session.get(StageORM, stage_id)
        if st is None:
            raise KeyError(f"unknown stage id {stage_id}")
        st.status = "completed"
        st.completed_at = _utcnow()

    def fail(self, stage_id: int, message: str = "") -> None:
        st = self.session.get(StageORM, stage_id)
        if st is None:
            raise KeyError(f"unknown stage id {stage_id}")
        st.status = "failed"
        st.completed_at = _utcnow()
        st.error_message = message or None

    def partial(self, stage_id: int, message: str = "") -> None:
        """Một giai đoạn đã tạo ra đầu ra nhưng không kết thúc hoàn chỉnh."""
        st = self.session.get(StageORM, stage_id)
        if st is None:
            raise KeyError(f"unknown stage id {stage_id}")
        st.status = "partial"
        st.completed_at = _utcnow()
        st.error_message = message or None

    def interrupt(self, stage_id: int, message: str = "") -> None:
        st = self.session.get(StageORM, stage_id)
        if st is None:
            raise KeyError(f"unknown stage id {stage_id}")
        st.status = "interrupted"
        st.completed_at = _utcnow()
        st.error_message = message or None

    def history(self) -> list[StageORM]:
        """Lịch sử lưu trữ bền vững đầy đủ (vẫn tồn tại sau khi tiến trình khởi động lại)."""
        return (
            self.session.query(StageORM)
            .filter(StageORM.run_id == self.run_id)
            .order_by(StageORM.ordinal.asc())
            .all()
        )
