"""Stage tracker — persists stage transitions so history survives restarts.

A partial or failed run must never look clean: a stage that did not reach
COMPLETED is reported as PARTIAL (if it produced output) or FAILED.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..storage.models import StageORM


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class StageTracker:
    """Records stage lifecycle against the DB-backed run."""

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
        """A stage that produced output but did not finish cleanly."""
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
        """Full persisted history (survives process restart)."""
        return (
            self.session.query(StageORM)
            .filter(StageORM.run_id == self.run_id)
            .order_by(StageORM.ordinal.asc())
            .all()
        )
