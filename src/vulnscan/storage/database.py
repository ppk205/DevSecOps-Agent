"""Database engine factory, session management, and init_db for SQLite."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

_engine = None
_SessionLocal: sessionmaker[Session] | None = None
_DEFAULT_DB = "vulnscan.db"


def get_engine(db_path: str | Path = _DEFAULT_DB):
    """Return (or create) a singleton engine for the given SQLite path."""
    global _engine
    if _engine is None:
        url = f"sqlite:///{db_path}"
        _engine = create_engine(url, echo=False, future=True)

        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return _engine


@contextlib.contextmanager
def get_session(db_path: str | Path = _DEFAULT_DB) -> Generator[Session, None, None]:
    """Context-managed session: commit on success, roll back on error."""
    engine = get_engine(db_path)
    factory = sessionmaker(bind=engine, future=True)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(db_path: str | Path = _DEFAULT_DB) -> None:
    """Create all tables (no-op if they already exist)."""
    engine = get_engine(db_path)
    Base.metadata.create_all(bind=engine)
