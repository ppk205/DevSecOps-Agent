"""Phase 2 backend: tools / settings / keys / usage / scans.

Keys live ONLY in the project-local ``.env`` + ``.providers/*.json``; every
response asserting on keys also asserts the fake secret never appears.
DB + cwd are isolated per-test via ``tmp_path`` + ``monkeypatch.chdir``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from vulnscan.storage.database import migrate
from vulnscan.web.app import create_app

FAKE_KEY = "sk-fake-Phase2-9999888877776666"


def _client(tmp_path: Path, monkeypatch) -> TestClient:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    engine = create_engine(f"sqlite:///{tmp_path / 'phase2.db'}")
    migrate(engine)
    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    client = TestClient(app)
    return client


def _csrf(client: TestClient) -> dict[str, str]:
    token = client.get("/api/health").cookies.get("vulnscan_csrf")
    assert token, "CSRF cookie missing"
    return {"X-CSRF-Token": token}


class TestTools:
    def test_shape(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        client = _client(tmp_path, monkeypatch)
        response = client.get("/api/tools")
        assert response.status_code == 200
        assert response.headers["X-Contract-Version"] == "1"
        tools = response.json()["tools"]
        names = {t["tool"] for t in tools}
        assert {"semgrep", "gitleaks", "spotbugs", "owasp-dependency-check"} <= names
        for item in tools:
            assert set(item) >= {"tool", "binary", "available", "path", "hint"}


class TestSettings:
    def test_get_defaults(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        client = _client(tmp_path, monkeypatch)
        body = client.get("/api/settings").json()["general"]
        assert body["timezone"] == "Asia/Saigon"
        assert body["profile"] == "fast"

    def test_put_roundtrip(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        client = _client(tmp_path, monkeypatch)
        response = client.put("/api/settings", json={"timeout": 900}, headers=_csrf(client))
        assert response.status_code == 200
        assert response.json()["general"]["timeout"] == 900
        assert client.get("/api/settings").json()["general"]["timeout"] == 900

    def test_put_rejects_bad_timezone(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        client = _client(tmp_path, monkeypatch)
        response = client.put(
            "/api/settings", json={"timezone": "Mars/Olympus"}, headers=_csrf(client)
        )
        assert response.status_code == 422


class TestKeys:
    def test_put_get_masked_never_leaks(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        client = _client(tmp_path, monkeypatch)
        put = client.put(
            "/api/settings/keys/t-alpha",
            json={"api_key": FAKE_KEY, "base_url": "https://example.test/v1", "label": "T Alpha"},
            headers=_csrf(client),
        )
        assert put.status_code == 200
        assert FAKE_KEY not in put.text
        assert put.json()["masked"].endswith("6666")
        listed = client.get("/api/settings/keys")
        assert listed.status_code == 200
        assert FAKE_KEY not in listed.text
        entry = next(k for k in listed.json()["keys"] if k["profile"] == "t-alpha")
        assert entry["configured"] is True
        assert entry["masked"].endswith("6666")

    def test_put_rejects_empty(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        client = _client(tmp_path, monkeypatch)
        response = client.put(
            "/api/settings/keys/t-empty", json={"api_key": "  "}, headers=_csrf(client)
        )
        assert response.status_code == 422

    def test_delete_removes_profile(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        client = _client(tmp_path, monkeypatch)
        headers = _csrf(client)
        client.put("/api/settings/keys/t-gone", json={"api_key": FAKE_KEY}, headers=headers)
        deleted = client.delete("/api/settings/keys/t-gone", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json()["deleted"] is True
        assert client.delete("/api/settings/keys/t-gone", headers=headers).status_code == 404

    def test_test_unreachable_returns_not_ok(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        client = _client(tmp_path, monkeypatch)
        headers = _csrf(client)
        client.put(
            "/api/settings/keys/t-offline",
            json={"api_key": FAKE_KEY, "base_url": "http://127.0.0.1:9"},
            headers=headers,
        )
        response = client.post("/api/settings/keys/t-offline/test", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is False
        assert FAKE_KEY not in response.text


class TestUsage:
    def test_budget_ceiling(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        client = _client(tmp_path, monkeypatch)
        body = client.get("/api/usage").json()
        assert body["total_budget"] == 50.0
        assert body["total_spent"] == 0.0
        assert body["available"] == 50.0


class TestScans:
    def test_create_list_filter(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import vulnscan.web.phase2_routes as routes

        calls: list[dict[str, str]] = []
        monkeypatch.setattr(
            routes, "_execute_web_scan", lambda *a: calls.append({"public_id": a[2]})
        )
        client = _client(tmp_path, monkeypatch)
        headers = _csrf(client)
        created = client.post(
            "/api/scans",
            json={"repository_url": "https://example.test/shop", "profile": "fast"},
            headers=headers,
        )
        assert created.status_code == 200
        run_id = created.json()["run_id"]
        assert len(calls) == 1
        listed = client.get("/api/scans").json()
        assert listed["total"] == 1
        assert listed["scans"][0]["run_id"] == run_id
        assert listed["scans"][0]["status"] == "queued"
        assert client.get("/api/scans", params={"status": "completed"}).json()["total"] == 0
        assert client.get("/api/scans", params={"status": "queued"}).json()["total"] == 1

    def test_create_hunt_requires_provider(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        import vulnscan.web.phase2_routes as routes

        seen: list[dict[str, str]] = []
        monkeypatch.setattr(
            routes, "_execute_web_scan", lambda *a: seen.append({"mode": a[3].get("mode")})
        )
        client = _client(tmp_path, monkeypatch)
        headers = _csrf(client)
        ok = client.post(
            "/api/scans",
            json={
                "repository_url": "https://example.test/shop",
                "mode": "hunt",
                "provider_profile": "kios-free",
            },
            headers=headers,
        )
        assert ok.status_code == 200
        assert seen and seen[0]["mode"] == "hunt"

    def test_execute_hunt_without_provider_fails_fast(
        self,
        tmp_path: Path,  # type: ignore[no-untyped-def]
    ) -> None:
        from vulnscan.storage.database import get_session
        from vulnscan.storage.models import RunORM, TargetORM
        from vulnscan.web.phase2_routes import _execute_web_scan as real

        db = str(tmp_path / "huntfail.db")
        engine = create_engine(f"sqlite:///{db}")
        migrate(engine)
        with get_session(db) as session:
            target = TargetORM(repository_url="local", commit_sha="0" * 40)
            session.add(target)
            session.flush()
            session.add(RunORM(target_id=target.id, public_id="web-hunt1", status="queued"))
            session.flush()
        real(
            db,
            str(tmp_path / "out"),
            "web-hunt1",
            {"checkout": "local", "repo": "local", "profile": "fast", "mode": "hunt"},
        )
        with get_session(db) as session:
            row = session.query(RunORM).filter_by(public_id="web-hunt1").first()
            assert row is not None and row.status == "failed"
            assert "provider" in (row.result_json or "")

    def test_execute_marks_failed_on_bad_checkout(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        import vulnscan.web.phase2_routes as routes
        from vulnscan.storage.database import get_session
        from vulnscan.storage.models import RunORM, TargetORM

        engine = create_engine(f"sqlite:///{tmp_path / 'exec.db'}")
        migrate(engine)
        with get_session(str(tmp_path / "exec.db")) as session:
            target = TargetORM(repository_url="local", commit_sha="0" * 40)
            session.add(target)
            session.flush()
            row = RunORM(target_id=target.id, public_id="web-test123", status="queued")
            session.add(row)
            session.flush()
            pk = row.id
        routes._execute_web_scan(
            str(tmp_path / "exec.db"),
            str(tmp_path / "out"),
            "web-test123",
            {
                "checkout": str(tmp_path / "no-such-dir"),
                "repo": "local",
                "commit": "",
                "profile": "fast",
            },
        )
        with get_session(str(tmp_path / "exec.db")) as session:
            row = session.get(RunORM, pk)
            assert row is not None and row.status == "failed"
            assert "errors" in (row.result_json or "")

    def test_run_adopts_queued_placeholder_row(self, tmp_path) -> None:
        """ScanService.run with a queued public_id must reuse the row (live polling)."""
        import subprocess
        from datetime import UTC, datetime

        from vulnscan.contracts import (
            CoverageRecord,
            CoverageUnitStatus,
            RunStatus,
            ScannerResult,
            ToolName,
        )
        from vulnscan.core.config import ScanConfig
        from vulnscan.core.scan_service import ScanService
        from vulnscan.scanners.base import (
            AdapterCapability,
            AdapterRegistry,
            ScannerAdapter,
        )
        from vulnscan.storage.database import get_session, migrate
        from vulnscan.storage.models import RunORM, TargetORM

        class _FakeAdapter(ScannerAdapter):
            tool = ToolName.SEMGREP
            binary_name = "fixture"

            def capabilities(self):
                return AdapterCapability(self.tool, available=True)

            def run(self, spec, *, workdir):
                now = datetime.now(UTC)
                return ScannerResult(
                    run_id=spec.run_id,
                    tool=self.tool,
                    tool_version="test",
                    adapter_version="test",
                    status=RunStatus.COMPLETED,
                    started_at=now,
                    finished_at=now,
                    observations=[],
                    coverage_records=[
                        CoverageRecord(
                            run_id=spec.run_id,
                            tool=self.tool,
                            tool_version="test",
                            source_snapshot=spec.target_commit_sha,
                            unit_path="Example.java",
                            eligible=True,
                            status=CoverageUnitStatus.ANALYZED,
                            analyzed_at=now,
                        )
                    ],
                )

        registry = AdapterRegistry()
        registry.register(_FakeAdapter())
        leaks = _FakeAdapter()
        leaks.tool = ToolName.GITLEAKS
        registry.register(leaks)
        db = str(tmp_path / "adopt.db")
        migrate(create_engine(f"sqlite:///{db}"))
        with get_session(db) as session:
            target = TargetORM(repository_url="local", commit_sha="0" * 40)
            session.add(target)
            session.flush()
            session.add(RunORM(target_id=target.id, public_id="web-abc123", status="queued"))
            session.flush()

        repo = tmp_path / "tiny"
        repo.mkdir()
        (repo / "Example.java").write_text("class Example {}")
        for args in (
            ["init"],
            ["add", "."],
            ["-c", "user.name=T", "-c", "user.email=t@e", "commit", "-m", "x"],
        ):
            subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

        service = ScanService(db, registry)
        result = service.run(
            str(repo),
            ScanConfig(output_dir=str(tmp_path / "reports")),
            repo="local",
            public_id="web-abc123",
        )
        assert result["run_id"] == "web-abc123", result.get("errors")
        assert result["status"] == "completed", result.get("errors")
        with get_session(db) as session:
            rows = session.query(RunORM).filter_by(public_id="web-abc123").all()
            assert len(rows) == 1
            assert rows[0].status == "completed"

    def test_create_rejects_bad_profile(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        client = _client(tmp_path, monkeypatch)
        response = client.post(
            "/api/scans",
            json={"repository_url": "https://example.test/x", "profile": "deep"},
            headers=_csrf(client),
        )
        assert response.status_code == 422

    def test_create_requires_csrf(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        client = _client(tmp_path, monkeypatch)
        response = client.post("/api/scans", json={"repository_url": "https://example.test/x"})
        assert response.status_code == 403
