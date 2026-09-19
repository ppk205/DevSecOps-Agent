"""Shared fixtures for platform tests (T01)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

# Make src importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from vulnscan.storage.database import Base


@pytest.fixture()
def in_memory_engine():
    """In-memory SQLite engine with foreign keys enabled."""
    engine = create_engine("sqlite:///:memory:", echo=False, future=True)

    @event.listens_for(engine, "connect")
    def _set_pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture()
def session(in_memory_engine) -> Session:
    factory = sessionmaker(bind=in_memory_engine, future=True)
    s = factory()
    yield s
    s.close()


@pytest.fixture()
def sample_spec():
    """A minimal ScanSpecification for testing (uses real contract)."""
    from vulnscan.contracts import ScanSpecification, ToolConfig
    return ScanSpecification(
        target_repository_url="https://github.com/test/repo",
        target_commit_sha="deadbeef00000000000000000000000000000000",
        tools=[ToolConfig(tool="semgrep")],
    )
