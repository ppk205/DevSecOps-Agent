"""Phase 2 backend: tools / settings / keys / usage / scans.

Keys live ONLY in the project-local ``.env`` + ``.providers/*.json``; every
response asserting on keys also asserts the fake secret never appears.
DB + cwd are isolated per-test via ``tmp_path`` + ``monkeypatch.chdir``.
"""

from __future__ import annotations

import subprocess
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
        assert names == {
            "native-hunt",
            "semgrep",
            "gitleaks",
            "trivy",
            "owasp-dependency-check",
            "codeql",
        }
        assert response.json()["profiles"] == {
            "fast": ["native-hunt", "semgrep", "gitleaks"],
            "full": ["native-hunt", "semgrep", "gitleaks", "trivy", "owasp-dependency-check"],
        }
        assert next(item for item in tools if item["tool"] == "native-hunt")["available"] is True
        for item in tools:
            assert set(item) >= {"tool", "binary", "available", "path", "hint"}

    def test_container_scanners_count_when_image_present(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        # Full scans can run Dependency-Check in the scanner image.
        from vulnscan.scanners import platform
        from vulnscan.web import phase2

        monkeypatch.setattr(
            platform, "which", lambda b: "/usr/bin/docker" if b == "docker" else None
        )
        monkeypatch.setattr(phase2, "_scanner_image_present", lambda: True)
        tools = {t["tool"]: t for t in phase2.probe_tools()}
        dependency_check = tools["owasp-dependency-check"]
        assert dependency_check["available"] is True
        assert dependency_check["path"] == "docker:devsecops-agent-scanners:0.2.0"
        assert "full profile" in dependency_check["hint"]
        assert tools["trivy"]["available"] is False
        assert tools["gitleaks"]["available"] is False

        monkeypatch.setattr(phase2, "_scanner_image_present", lambda: False)
        tools = {t["tool"]: t for t in phase2.probe_tools()}
        assert tools["owasp-dependency-check"]["available"] is False


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

    def test_put_rejects_contract_invalid_id_without_storing_key(  # type: ignore[no-untyped-def]
        self, tmp_path: Path, monkeypatch
    ) -> None:
        client = _client(tmp_path, monkeypatch)
        headers = _csrf(client)
        for profile in ("deepseek_test", "9lives"):
            response = client.put(
                f"/api/settings/keys/{profile}", json={"api_key": FAKE_KEY}, headers=headers
            )
            assert response.status_code == 422
            assert "lowercase letters, digits or hyphens" in response.json()["detail"]
            assert FAKE_KEY not in response.text
        env = tmp_path / ".env"
        assert not env.exists() or FAKE_KEY not in env.read_text(encoding="utf-8")
        assert (
            client.post("/api/settings/keys/deepseek_test/test", headers=headers).status_code == 422
        )

    def test_put_key_only_preserves_headers(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from vulnscan.providers.profile_store import load_profile

        client = _client(tmp_path, monkeypatch)
        headers = _csrf(client)
        first = client.put(
            "/api/settings/keys/t-hdr",
            json={"api_key": FAKE_KEY, "base_url": "https://example.test/v1", "label": "T Hdr"},
            headers=headers,
        )
        assert first.status_code == 200
        # Simulate a profile that needs a routing header, then update only the key.
        prof = load_profile("t-hdr")
        prof.headers = {"x-opencode-session": "devsecops-agent"}
        from vulnscan.providers.profile_store import save_profile

        save_profile(prof)
        second = client.put("/api/settings/keys/t-hdr", json={"api_key": FAKE_KEY}, headers=headers)
        assert second.status_code == 200
        assert load_profile("t-hdr").headers == {"x-opencode-session": "devsecops-agent"}

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

    def test_create_passes_every_scan_choice(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import vulnscan.web.phase2_routes as routes

        seen: list[dict[str, object]] = []
        monkeypatch.setattr(routes, "_execute_web_scan", lambda *a: seen.append(a[3]))
        client = _client(tmp_path, monkeypatch)
        body = {
            "repository_url": "https://example.test/shop",
            "commit_sha": "a" * 40,
            "mode": "hunt",
            "ai_review": False,
            "ai_report": False,
            "laya": False,
            "fail_on": "critical",
            "allow_cloud_model": True,
        }
        response = client.post("/api/scans", json=body, headers=_csrf(client))
        assert response.status_code == 200
        scenario = client.get(f"/api/scans/{response.json()['run_id']}").json()["scenario"]
        assert scenario["mode"] == "hunt" and scenario["laya"] is False
        assert scenario["profile"] == "fast" and scenario["ai_report"] is False
        params = seen[0]
        assert params["allow_cloud_model"] is True
        assert params["commit"] == "a" * 40
        assert (params["ai_review"], params["ai_report"], params["laya"]) == (False, False, False)
        assert params["fail_on"] == "critical"

    def test_execute_keeps_explicit_choices_and_legacy_hunt_default(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        import vulnscan.core.config as config_module
        from vulnscan.web.phase2_routes import _execute_web_scan

        captured: list[dict[str, object]] = []

        def fake_resolve(profile, config, **flags):  # type: ignore[no-untyped-def]
            captured.append(flags)
            raise ValueError("stop after config")

        monkeypatch.setattr(config_module, "resolve_config", fake_resolve)
        base = {"checkout": "x", "repo": "x", "profile": "fast", "mode": "hunt"}
        explicit = {"ai_review": False, "ai_report": False, "laya": False, "fail_on": "none"}
        _execute_web_scan(str(tmp_path / "x.db"), str(tmp_path), "web-1", {**base, **explicit})
        _execute_web_scan(str(tmp_path / "x.db"), str(tmp_path), "web-2", dict(base))
        assert captured[0]["ai_review"] is False and captured[0]["ai_report"] is False
        assert captured[0]["laya"] is False and captured[0]["fail_on"] == "none"
        # Older clients that send only mode=hunt keep review and report on.
        assert captured[1]["ai_review"] is True and captured[1]["ai_report"] is True
        assert captured[1]["laya"] is None and captured[1]["fail_on"] == "high"
        # allow_cloud_model=False turns every model stage off, whatever else was asked.
        denied = {**base, "allow_cloud_model": False, "ai_review": True, "ai_report": True}
        _execute_web_scan(str(tmp_path / "x.db"), str(tmp_path), "web-3", denied)
        assert captured[2]["mode"] == "deterministic"
        assert captured[2]["ai_review"] is False and captured[2]["ai_report"] is False
        allowed = {**base, "allow_cloud_model": True}
        _execute_web_scan(str(tmp_path / "x.db"), str(tmp_path), "web-4", allowed)
        assert captured[3]["mode"] == "hunt"

    def test_ir11_worker_loads_saved_provider_before_scan(self, tmp_path, monkeypatch):
        from types import SimpleNamespace

        from vulnscan.core.scan_service import ScanService
        from vulnscan.infra.envfile import EnvFile
        from vulnscan.providers.credentials import load_api_key
        from vulnscan.web.phase2_routes import _execute_web_scan

        key_env = "WEB_WORKER_TEST_API_KEY"
        monkeypatch.delenv(key_env, raising=False)

        def load_saved_key(_store):
            monkeypatch.setenv(key_env, "fixture-key")

        observed = []

        def run(_service, _checkout, config, **_kwargs):
            observed.append((config.provider_model, load_api_key(key_env)))

        monkeypatch.setattr(EnvFile, "load_into_environ", load_saved_key)
        monkeypatch.setattr(ScanService, "run", run)
        monkeypatch.setattr(
            "vulnscan.core.source.resolve_source",
            lambda *_args, **_kwargs: SimpleNamespace(checkout=str(tmp_path), commit="abc"),
        )
        _execute_web_scan(
            str(tmp_path / "scan.db"),
            str(tmp_path),
            "web-key",
            {
                "checkout": str(tmp_path),
                "repo": str(tmp_path),
                "profile": "full",
                "mode": "deterministic",
                "ai_report": True,
                "provider_profile": "offline-fixture",
                "provider_model": "requested-model",
            },
        )
        assert observed == [("requested-model", "fixture-key")]

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

    def test_execute_hunt_without_key_skips_with_reason(
        self,
        tmp_path: Path,  # type: ignore[no-untyped-def]
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        import vulnscan.providers.profile_store as store
        from vulnscan.storage.database import get_session
        from vulnscan.storage.models import RunORM, TargetORM
        from vulnscan.web.phase2_routes import _execute_web_scan as real

        monkeypatch.setattr(store, "default_profile", lambda base=None: None)
        db = str(tmp_path / "huntskip.db")
        engine = create_engine(f"sqlite:///{db}")
        migrate(engine)
        with get_session(db) as session:
            target = TargetORM(repository_url="local", commit_sha="0" * 40)
            session.add(target)
            session.flush()
            session.add(RunORM(target_id=target.id, public_id="web-hunt1", status="queued"))
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
        real(
            db,
            str(tmp_path / "out"),
            "web-hunt1",
            {"checkout": str(repo), "repo": "local", "profile": "fast", "mode": "hunt"},
        )
        with get_session(db) as session:
            row = session.query(RunORM).filter_by(public_id="web-hunt1").first()
            assert row is not None and row.status == "completed"
            assert "no provider key" in (row.result_json or "")

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
        native = _FakeAdapter()
        native.tool = ToolName.NATIVE_HUNT
        registry.register(native)
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
