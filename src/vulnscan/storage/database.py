"""Path-keyed SQLite engines and additive migrations."""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Generator
from pathlib import Path
from typing import Any

from filelock import FileLock
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from .models import Base

_engines: dict[str, Engine] = {}


def get_engine(db_path: str | Path = "vulnscan.db") -> Engine:
    key = str(Path(db_path).resolve()) if str(db_path) != ":memory:" else ":memory:"
    if key not in _engines:
        if key != ":memory:":
            Path(key).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            f"sqlite:///{key}",
            connect_args={"check_same_thread": False},
            **({"poolclass": StaticPool} if key == ":memory:" else {}),
        )

        @event.listens_for(engine, "connect")
        def configure(conn: sqlite3.Connection, _: Any) -> None:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=10000")

        _engines[key] = engine
    return _engines[key]


@contextlib.contextmanager
def get_session(db_path: str | Path = "vulnscan.db") -> Generator[Session, None, None]:
    with Session(get_engine(db_path), expire_on_commit=False) as session:
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise


def migrate(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        columns = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(runs)")}
        for name, sql_type in {
            "public_id": "VARCHAR(80)",
            "parent_id": "INTEGER",
            "result_json": "TEXT NOT NULL DEFAULT '{}'",
            "events_json": "TEXT NOT NULL DEFAULT '[]'",
            "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            if name not in columns:
                conn.exec_driver_sql(f"ALTER TABLE runs ADD COLUMN {name} {sql_type}")
        conn.exec_driver_sql("CREATE UNIQUE INDEX IF NOT EXISTS runs_public_id ON runs(public_id)")
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"
        )
        conn.exec_driver_sql("INSERT OR IGNORE INTO schema_migrations VALUES (1)")
        if not conn.exec_driver_sql("SELECT 1 FROM schema_migrations WHERE version = 2").first():
            for table, names in {
                "targets": ["created_at"],
                "runs": ["created_at", "updated_at"],
                "stages": ["started_at", "completed_at"],
                "findings": ["created_at"],
            }.items():
                for name in names:
                    conn.exec_driver_sql(
                        f"UPDATE {table} SET {name} = replace({name}, ' ', 'T') || '+00:00' WHERE {name} IS NOT NULL AND {name} NOT LIKE '%+00:00' AND {name} NOT LIKE '%Z'"
                    )
            conn.exec_driver_sql("INSERT INTO schema_migrations VALUES (2)")


def init_db(db_path: str | Path = "vulnscan.db") -> None:
    engine = get_engine(db_path)
    if str(db_path) == ":memory:":
        migrate(engine)
    else:
        with FileLock(str(Path(db_path).resolve()) + ".migration.lock"):
            migrate(engine)
