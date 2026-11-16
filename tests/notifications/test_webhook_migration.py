"""FR-75: old notification receipts survive the webhook metadata migration."""

from sqlalchemy import create_engine

from vulnscan.storage.database import migrate


def test_existing_delivery_is_preserved_through_repeated_migration(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            """CREATE TABLE notification_deliveries (
                id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL,
                channel VARCHAR(16) NOT NULL, events_json TEXT NOT NULL,
                selected_events_json TEXT NOT NULL, status VARCHAR(16) NOT NULL,
                detail TEXT NOT NULL, created_at VARCHAR(64), updated_at VARCHAR(64),
                UNIQUE (run_id, channel)
            )"""
        )
        conn.exec_driver_sql(
            "INSERT INTO notification_deliveries VALUES (1, 1, 'discord', '[]', '[]', 'sent', 'retained', NULL, NULL)"
        )
    migrate(engine)
    migrate(engine)
    with engine.connect() as conn:
        row = conn.exec_driver_sql(
            "SELECT channel, status, detail, delivery_key, payload_json, destination_fingerprint FROM notification_deliveries"
        ).one()
        assert tuple(row) == ("discord", "sent", "retained", None, None, None)
        assert (
            conn.exec_driver_sql("SELECT version FROM schema_migrations WHERE version=9").scalar()
            == 9
        )
