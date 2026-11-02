"""SQLAlchemy ORM models for the DevSecOps-Agent persistence layer.

Maps core entities to SQLite tables. Contract payloads (ScanSpecification,
RunManifest, findings, assessments, coverage records) are stored as JSON blobs
so the ORM stays decoupled from contract evolution.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


class UTCDateTime(TypeDecorator[datetime]):
    """Store explicit UTC offsets; read legacy UTC-naive SQLite values safely."""

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
    """A registered target repository."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    repository_url: Mapped[str] = mapped_column(String(512), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    runs: Mapped[list[RunORM]] = relationship("RunORM", back_populates="target")


class RunORM(Base):
    """One scan run — links to a target and tracks overall status."""

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
    """A lifecycle stage within a run."""

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
    """A grouped finding (serialized Finding contract blob)."""

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
    """A persisted pipeline/log event for one scan run (Phase 1 skeleton).

    Kinds: ``log`` | ``stage`` | ``ai_step`` | ``ai_proposal`` |
    ``verification_result``. Ordering key is (run_id, seq); ``payload_json``
    holds the optional structured payload. Rows are append-only.
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
    """An AI-generated fix proposal for one finding.

    The model only writes the unified diff — it never touches source.
    ``status``: proposed → applied → verified (or failed). ``overlay_path``
    points at the patched copy under artifacts (never the user checkout).
    ``verification_json`` records the rescan proof (rule refired or not).
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
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    run: Mapped[RunORM] = relationship("RunORM")
