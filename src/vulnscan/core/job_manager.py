"""Job manager — gửi yêu cầu quét, theo dõi các lần chạy, thực thi chỉ một lần chạy tại một thời điểm.

Việc thử lại là một *lần thử mới*: nó bảo toàn các artifact trước đó và lịch sử các giai
đoạn nhưng không bao giờ tái sử dụng run id đã thất bại. Chỉ một lần chạy có thể ở trạng thái RUNNING tại một thời điểm.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.orm import Session

from ..contracts import ScanSpecification
from ..storage.models import RunORM, TargetORM


class RunAlreadyRunningError(RuntimeError):
    """Một lần quét khác hiện đã ở trạng thái RUNNING."""


class RunNotFoundError(KeyError):
    """Không có lần chạy nào với id được cung cấp."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


class JobManager:
    """Gửi và theo dõi các lần quét đối với một session."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def _running(self) -> RunORM | None:
        return self.session.query(RunORM).filter(RunORM.status == "running").first()

    def submit_scan(self, spec: ScanSpecification) -> int:
        """Tạo một lần chạy trong hàng đợi cho mục tiêu đã ghim của spec.

        Ném ra RunAlreadyRunningError nếu một lần chạy khác đang được tiến hành.
        """
        if self._running() is not None:
            raise RunAlreadyRunningError("a scan run is already RUNNING")

        target = (
            self.session.query(TargetORM)
            .filter(
                TargetORM.repository_url == spec.target_repository_url,
                TargetORM.commit_sha == spec.target_commit_sha,
            )
            .first()
        )
        if target is None:
            target = TargetORM(
                repository_url=spec.target_repository_url,
                commit_sha=spec.target_commit_sha,
            )
            self.session.add(target)
            self.session.flush()

        spec = spec.model_copy(update={"run_id": "run-" + uuid4().hex})
        run = RunORM(
            public_id=spec.run_id,
            target_id=target.id,
            attempt=1,
            status="queued",
            scan_spec_json=spec.model_dump_json(),
        )
        self.session.add(run)
        self.session.flush()
        return run.id

    def retry(self, run_id: int) -> int:
        """Tạo một lần thử mới cho một lần chạy bị thất bại/gián đoạn.

        Lần chạy ban đầu được giữ nguyên không đổi; lần chạy mới kế thừa mục
        tiêu của nó và tăng bộ đếm số lần thử. Các artifact trước đó được
        bảo toàn bởi ArtifactStore (được đánh khóa theo run+attempt).
        """
        prior = self._get(run_id)
        if self._running() is not None:
            raise RunAlreadyRunningError("a scan run is already RUNNING")
        if prior.status not in {"failed", "interrupted", "completed_with_errors"}:
            raise ValueError(f"cannot retry a run in status {prior.status!r}")

        spec = ScanSpecification.model_validate_json(prior.scan_spec_json)
        spec.run_id = "run-" + uuid4().hex
        next_attempt = prior.attempt + 1
        run = RunORM(
            target_id=prior.target_id,
            attempt=next_attempt,
            status="queued",
            scan_spec_json=spec.model_dump_json(),
            public_id=spec.run_id,
            parent_id=prior.id,
        )
        self.session.add(run)
        self.session.flush()
        return run.id

    def mark_running(self, run_id: int) -> None:
        run = self._get(run_id)
        run.status = "running"

    def update_run_status(self, run_id: int, status: str) -> None:
        run = self._get(run_id)
        run.status = status
        run.updated_at = _utcnow()

    def get_run(self, run_id: int) -> RunORM:
        return self._get(run_id)

    def list_runs(self) -> list[RunORM]:
        return self.session.query(RunORM).order_by(RunORM.id.desc()).all()

    def _get(self, run_id: int) -> RunORM:
        run = self.session.get(RunORM, run_id)
        if run is None:
            raise RunNotFoundError(run_id)
        return run
