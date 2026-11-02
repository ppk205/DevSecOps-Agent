"""Phase 1 foundation: health, scan-events table, SSE skeleton, SPA fallback.

Jinja legacy routes must keep working (covered by tests/web/test_dashboard.py);
this module covers only the new surface.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from vulnscan.storage.database import migrate
from vulnscan.storage.models import RunORM, ScanEventORM, TargetORM
from vulnscan.web.app import create_app


def _seeded_client(tmp_path: Path, with_events: bool = True) -> TestClient:
    engine = create_engine(f"sqlite:///{tmp_path / 'phase1.db'}")
    migrate(engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        target = TargetORM(repository_url="https://example.test/repo", commit_sha="c" * 40)
        session.add(target)
        session.flush()
        run = RunORM(target_id=target.id, status="running")
        session.add(run)
        session.flush()
        if with_events:
            session.add(
                ScanEventORM(
                    run_id=run.id,
                    seq=0,
                    kind="stage",
                    stage="scan",
                    message="scan started",
                    created_at=datetime.now(UTC),
                )
            )
            session.add(
                ScanEventORM(
                    run_id=run.id,
                    seq=1,
                    kind="log",
                    stage="scan",
                    message="rule pack loaded",
                    created_at=datetime.now(UTC),
                )
            )
        session.commit()
        run_pk = run.id
    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    with TestClient(app) as test_client:
        test_client.run_pk = run_pk  # type: ignore[attr-defined]
        return test_client


class TestHealth:
    def test_health_contract(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.headers["X-Contract-Version"] == "1"


class TestEventsTable:
    def test_migration_creates_scan_events(self, tmp_path: Path) -> None:
        engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
        migrate(engine)
        assert "scan_events" in inspect(engine).get_table_names()

    def test_history_returns_seeded_rows(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get(f"/api/scans/{client.run_pk}/events/history")
        assert response.status_code == 200
        body = response.json()
        assert body["run_id"] == client.run_pk
        assert [e["seq"] for e in body["events"]] == [0, 1]
        assert body["events"][0]["kind"] == "stage"
        assert body["next_cursor"] == 2

    def test_history_empty_for_fresh_run(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path, with_events=False)
        response = client.get(f"/api/scans/{client.run_pk}/events/history")
        assert response.status_code == 200
        assert response.json()["events"] == []

    def test_history_404(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        assert client.get("/api/scans/9999/events/history").status_code == 404


class TestSseSkeleton:
    def test_stream_emits_hello_events_live(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get(f"/api/scans/{client.run_pk}/events")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        text = response.text
        assert "event: hello" in text
        assert "event: live" in text
        assert "scan started" in text

    def test_stream_respects_last_event_id(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get(f"/api/scans/{client.run_pk}/events", headers={"last-event-id": "0"})
        assert response.status_code == 200
        assert "scan started" not in response.text
        assert "rule pack loaded" in response.text

    def test_stream_404(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        assert client.get("/api/scans/9999/events").status_code == 404


class TestSpaFallback:
    def test_no_dist_no_app_route(self, tmp_path: Path) -> None:
        # No web-ui/dist in a bare checkout state for this tmp engine —
        # /app/* is simply unmounted (404), Jinja keeps working.
        client = _seeded_client(tmp_path)
        assert client.get("/").status_code == 200
        assert client.get("/").headers.get("X-Pitwall-Legacy") == "true"

    def test_spa_dir_serves_index_and_fallback(self, tmp_path: Path) -> None:
        import vulnscan.web.app as app_module

        real_file = Path(app_module.__file__)
        fake_static = real_file.with_name("static") / "app"
        fake_static.mkdir(parents=True, exist_ok=True)
        try:
            (fake_static / "index.html").write_text("<html>pitwall</html>")
            (fake_static / "assets").mkdir(exist_ok=True)
            (fake_static / "assets" / "app.js").write_text("console.log(1)")
            engine = create_engine(f"sqlite:///{tmp_path / 'spa.db'}")
            migrate(engine)
            spa_client = TestClient(create_app(engine=engine))
            index = spa_client.get("/app/")
            assert index.status_code == 200
            assert "pitwall" in index.text
            deep = spa_client.get("/app/findings/whatever")
            assert deep.status_code == 200
            assert "pitwall" in deep.text
            asset = spa_client.get("/app/assets/app.js")
            assert asset.status_code == 200
        finally:
            shutil.rmtree(fake_static, ignore_errors=True)
            static_parent = real_file.with_name("static")
            if static_parent.is_dir() and not any(static_parent.iterdir()):
                static_parent.rmdir()
