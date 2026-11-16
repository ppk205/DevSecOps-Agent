"""Các model SQLAlchemy ORM cho tầng lưu trữ của DevSecOps-Agent.

Ánh xạ các thực thể cốt lõi sang bảng SQLite. Payload của contract (ScanSpecification,
RunManifest, finding, assessment, bản ghi coverage) được lưu dưới dạng blob JSON
để ORM không bị phụ thuộc vào sự phát triển của contract.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    """Lớp declarative base dùng chung cho tất cả các model ORM."""


class UTCDateTime(TypeDecorator[datetime]):
    """Lưu độ lệch UTC rõ ràng; đọc an toàn các giá trị SQLite không có múi giờ (UTC-naive) cũ."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("timestamp must be timezone aware")
        return value.astimezone(UTC).isoformat()

    def process_result_value(self, value: str | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TargetORM(Base):
    """Một repository mục tiêu đã đăng ký."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    repository_url: Mapped[str] = mapped_column(String(512), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    runs: Mapped[list[RunORM]] = relationship("RunORM", back_populates="target")


class RunORM(Base):
    """Một lượt chạy scan — liên kết tới một mục tiêu và theo dõi trạng thái tổng thể."""

    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    scan_spec_json: Mapped[str] = mapped_column(Text, default="{}")
    public_id: Mapped[str | None] = mapped_column(String(80), unique=True, nullable=True)
    parent_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    events_json: Mapped[str] = mapped_column(Text, default="[]")
    cancel_requested: Mapped[int] = mapped_column(Integer, default=0)
    findings_revision: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, onupdate=_utcnow)

    target: Mapped[TargetORM] = relationship("TargetORM", back_populates="runs")
    stages: Mapped[list[StageORM]] = relationship(
        "StageORM", back_populates="run", order_by="StageORM.ordinal"
    )
    findings: Mapped[list[FindingORM]] = relationship("FindingORM", back_populates="run")


class StageORM(Base):
    """Một giai đoạn vòng đời (lifecycle stage) trong một lượt chạy."""

    __tablename__ = "stages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"))
    ordinal: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    run: Mapped[RunORM] = relationship("RunORM", back_populates="stages")


class FindingORM(Base):
    """Một finding đã gom nhóm (blob contract Finding đã tuần tự hóa)."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"))
    finding_json: Mapped[str] = mapped_column(Text, default="{}")
    finding_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    search_text: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    run: Mapped[RunORM] = relationship("RunORM", back_populates="findings")


class ScanEventORM(Base):
    """Một sự kiện pipeline/log được lưu trữ cho một lượt chạy scan (khung Phase 1).

    Các loại: ``log`` | ``stage`` | ``ai_step`` | ``ai_proposal`` |
    ``verification_result``. Khóa sắp xếp là (run_id, seq); ``payload_json``
    chứa payload có cấu trúc tùy chọn. Các hàng chỉ cho phép ghi nối tiếp (append-only).
    """

    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"))
    seq: Mapped[int] = mapped_column(Integer, default=0)
    kind: Mapped[str] = mapped_column(String(32), default="log")
    stage: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    run: Mapped[RunORM] = relationship("RunORM")


class FixProposalORM(Base):
    """Một đề xuất sửa lỗi do AI tạo ra cho một finding.

    Model chỉ tạo unified diff — không bao giờ chạm vào mã nguồn gốc.
    ``status``: proposed → applied → verified (hoặc failed). ``overlay_path``
    trỏ tới bản sao đã vá nằm trong thư mục artifacts (không bao giờ là checkout của người dùng).
    ``verification_json`` ghi nhận bằng chứng rescan (rule có kích hoạt lại hay không).
    """

    __tablename__ = "fix_proposals"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"))
    finding_id: Mapped[str] = mapped_column(String(80))
    diff_text: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="proposed")
    model: Mapped[str | None] = mapped_column(String(80), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    overlay_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_json: Mapped[str] = mapped_column(Text, default="{}")
    provenance_json: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    run: Mapped[RunORM] = relationship("RunORM")


class RemediationAttemptORM(Base):
    """Retained application or publication attempt for one proposal."""

    __tablename__ = "remediation_attempts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    proposal_id: Mapped[int] = mapped_column(ForeignKey("fix_proposals.id"))
    kind: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(16))
    request_json: Mapped[str] = mapped_column(Text, default="{}")
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, onupdate=_utcnow)


class NotificationORM(Base):
    """Một thông báo hướng tới người dùng cho một lượt chạy scan.

    Các loại: ``scan_completed`` | ``gate_failed``. Các hàng được tạo một lần cho mỗi
    (run_id, kind) bởi ``record_scan_notification`` và được xác nhận qua
    ``POST /api/notifications/{id}/ack`` (thiết lập ``is_read``).
    """

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"))
    kind: Mapped[str] = mapped_column(String(32), default="scan_completed")
    message: Mapped[str] = mapped_column(Text, default="")
    is_read: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    run: Mapped[RunORM] = relationship("RunORM")


class NotificationDeliveryORM(Base):
    """One outbound digest per run/channel; an atomic claim prevents duplicates."""

    __tablename__ = "notification_deliveries"
    __table_args__ = (UniqueConstraint("run_id", "channel"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"))
    channel: Mapped[str] = mapped_column(String(16))
    events_json: Mapped[str] = mapped_column(Text, default="[]")
    selected_events_json: Mapped[str] = mapped_column(Text, default="[]")
    delivery_key: Mapped[str | None] = mapped_column(String(36), nullable=True)
    payload_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    destination_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    detail: Mapped[str] = mapped_column(Text, default="Awaiting event selection")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, onupdate=_utcnow)
