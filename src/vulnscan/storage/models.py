"""SQLAlchemy ORM models for the DevSecOps-Agent persistence layer.

Maps core entities to SQLite tables. Contract payloads (ScanSpecification,
RunManifest, findings, assessments, coverage records) are stored as JSON blobs
so the ORM stays decoupled from contract evolution.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TargetORM(Base):
    """A registered target repository."""
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    repository_url: Mapped[str] = mapped_column(String(512), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    runs: Mapped[list[RunORM]] = relationship("RunORM", back_populates="target")


class RunORM(Base):
    """One scan run — links to a target and tracks overall status."""
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    scan_spec_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    target: Mapped[TargetORM] = relationship("TargetORM", back_populates="runs")
    stages: Mapped[list[StageORM]] = relationship("StageORM", back_populates="run", order_by="StageORM.ordinal")
    findings: Mapped[list[FindingORM]] = relationship("FindingORM", back_populates="run")


class StageORM(Base):
    """A lifecycle stage within a run."""
    __tablename__ = "stages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"))
    ordinal: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    run: Mapped[RunORM] = relationship("RunORM", back_populates="stages")


class FindingORM(Base):
    """A grouped finding (serialized Finding contract blob)."""
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"))
    finding_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    run: Mapped[RunORM] = relationship("RunORM", back_populates="findings")
