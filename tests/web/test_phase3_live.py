"""Phase 3 live pipeline backend: event emission, SSE tail, detail, cancel/retry."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnscan.storage.database import migrate
from vulnscan.storage.models import RunORM, ScanEventORM, StageORM, TargetORM
from vulnscan.web.app import create_app


def _seeded(tmp_path: Path, status: str = "running") -> tuple[TestClient, int]:
    engine = create_engine(f"sqlite:///{tmp_path / 'phase3.db'}")
    migrate(engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        target = TargetORM(repository_url="https://example.test/shop", commit_sha="a" * 40)
        session.add(target)
        session.flush()
        run = RunORM(target_id=target.id, status=status, result_json='{"gate": "unknown"}')
        session.add(run)
        session.flush()
        for ordinal, name in enumerate(["intake", "scanners"]):
            session.add(
                StageORM(
                    run_id=run.id,
                    ordinal=ordinal,
                    name=name,
                    status="completed" if ordinal == 0 else "running",
                )
            )
        session.add(
            ScanEventORM(
                run_id=run.id,
                seq=0,
                kind="stage",
                stage="intake",
                message="intake → completed",
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
        pk = run.id
    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    return TestClient(app), pk


class TestScanDetail:
    def test_detail_shape(self, tmp_path: Path) -> None:
        client, pk = _seeded(tmp_path)
        body = client.get(f"/api/scans/{pk}").json()
        assert body["run_id"] == pk
        assert body["status"] == "running"
        assert {s["name"] for s in body["stages"]} >= {"intake", "scanners"}
        assert body["ai"]["assessments"] == []
        assert body["event_count"] == 1
        assert body["event_cursor"] == 0

    def test_detail_404(self, tmp_path: Path) -> None:
        client, _ = _seeded(tmp_path)
        assert client.get("/api/scans/9999").status_code == 404


class TestLiveSse:
    def test_terminal_run_ends_with_done(self, tmp_path: Path) -> None:
        client, pk = _seeded(tmp_path, status="completed")
        response = client.get(f"/api/scans/{pk}/events")
        assert response.status_code == 200
        text = response.text
        assert "event: hello" in text
        assert "event: done" in text
        assert "intake" in text

    def test_resume_skips_seen(self, tmp_path: Path) -> None:
        client, pk = _seeded(tmp_path, status="completed")
        response = client.get(f"/api/scans/{pk}/events", headers={"last-event-id": "0"})
        assert response.status_code == 200
        assert "intake" not in response.text
        assert "event: done" in response.text


class TestCancelRetry:
    def _headers(self, client: TestClient) -> dict[str, str]:
        token = client.get("/api/health").cookies.get("vulnscan_csrf")
        assert token, "CSRF cookie missing"
        return {"X-CSRF-Token": token}

    def test_cancel_queued_flips(self, tmp_path: Path) -> None:
        engine = create_engine(f"sqlite:///{tmp_path / 'c.db'}")
        migrate(engine)
        factory = sessionmaker(bind=engine)
        with factory() as session:
            target = TargetORM(repository_url="https://example.test/q", commit_sha="b" * 40)
            session.add(target)
            session.flush()
            run = RunORM(target_id=target.id, status="queued")
            session.add(run)
            session.commit()
            pk = run.id
        client = TestClient(create_app(engine=engine, export_dir=tmp_path / "exports"))
        body = client.post(f"/api/scans/{pk}/cancel", headers=self._headers(client)).json()
        assert body["status"] == "cancelled"
        assert body["cancel_requested"] is True

    def test_retry_clones_terminal(self, tmp_path: Path) -> None:
        client, pk = _seeded(tmp_path, status="failed")
        response = client.post(f"/api/scans/{pk}/retry", headers=self._headers(client))
        assert response.status_code == 201
        clone_id = response.json()["run_id"]
        detail = client.get(f"/api/scans/{clone_id}").json()
        assert detail["status"] == "queued"
        assert len(detail["stages"]) == 8

    def test_retry_rejects_live(self, tmp_path: Path) -> None:
        client, pk = _seeded(tmp_path, status="running")
        assert client.post(f"/api/scans/{pk}/retry", headers=self._headers(client)).status_code == 409


class TestEventEmission:
    def test_persist_writes_scan_events(self, tmp_path: Path, monkeypatch) -> None:
        """A fast deterministic scan emits scan_events rows without breaking."""
        import tempfile

        monkeypatch.chdir(tmp_path)
        from vulnscan.core.config import ScanConfig
        from vulnscan.core.scan_service import ScanService
        from vulnscan.storage.database import get_engine

        checkout = tmp_path / "repo"
        (checkout / "src").mkdir(parents=True)
        (checkout / "src" / "a.py").write_text("print('hi')\n", encoding="utf-8")
        # Minimal git repo so intake can pin a commit.
        import subprocess

        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        subprocess.run(
            ["git", "-C", str(checkout), "add", "-A"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(checkout), "-c", "user.email=t@t.t", "-c", "user.name=t",
             "commit", "-qm", "init"],
            check=True,
        )
        db = tmp_path / "live.db"
        service = ScanService(str(db))
        config = ScanConfig(output_dir=str(tmp_path / "out"), profile="fast")
        with tempfile.TemporaryDirectory() as _:
            result = service.run(str(checkout), config, repo="https://example.test/r")
        assert result["status"] in {"completed", "failed"}
        engine = get_engine(str(db))
        with sessionmaker(bind=engine)() as session:
            run = session.query(RunORM).order_by(RunORM.id.desc()).first()
            assert run is not None
            rows = (
                session.query(ScanEventORM)
                .filter(ScanEventORM.run_id == run.id)
                .order_by(ScanEventORM.seq)
                .all()
            )
            kinds = {r.kind for r in rows}
            assert len(rows) >= 3
            assert "stage" in kinds
            seqs = [r.seq for r in rows]
            assert seqs == sorted(seqs)
