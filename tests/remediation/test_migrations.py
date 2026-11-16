"""FR-49: remediation migration preserves legacy proposals and claims."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError

from vulnscan.storage.database import migrate


def test_legacy_proposal_survives_and_active_apply_claim_is_unique(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """CREATE TABLE fix_proposals (
                id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, finding_id VARCHAR(80) NOT NULL,
                diff_text TEXT NOT NULL, status VARCHAR(16) NOT NULL, model VARCHAR(80),
                error TEXT, overlay_path TEXT, verification_json TEXT NOT NULL, created_at VARCHAR(64)
            )"""
        )
        conn.exec_driver_sql(
            "INSERT INTO fix_proposals VALUES (1, 1, 'finding', 'legacy diff', 'verified', NULL, NULL, NULL, '{}', NULL)"
        )
    migrate(engine)
    migrate(engine)
    with engine.begin() as conn:
        row = conn.exec_driver_sql(
            "SELECT diff_text, status, provenance_json FROM fix_proposals"
        ).one()
        assert tuple(row) == ("legacy diff", "verified", "{}")
        assert (
            conn.exec_driver_sql("SELECT version FROM schema_migrations WHERE version=8").scalar()
            == 8
        )
        insert = "INSERT INTO remediation_attempts (proposal_id, kind, state, request_json, result_json, created_at, updated_at) VALUES (1, 'apply', 'running', '{}', '{}', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
        conn.exec_driver_sql(insert)
        with pytest.raises(IntegrityError):
            conn.exec_driver_sql(insert)
