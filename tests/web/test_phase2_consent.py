"""B7: the web New Scan form never sends code to a cloud model without consent."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from vulnscan.storage.database import migrate
from vulnscan.storage.models import RunORM
from vulnscan.web.app import create_app

FAKE_KEY = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2"


def _client(tmp_path: Path, monkeypatch) -> TestClient:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    engine = create_engine(f"sqlite:///{tmp_path / 'consent.db'}")
    migrate(engine)
    return TestClient(create_app(engine=engine, export_dir=tmp_path / "exports"))


def _csrf(client: TestClient) -> dict[str, str]:
    token = client.get("/api/health").cookies.get("vulnscan_csrf")
    assert token
    return {"X-CSRF-Token": token}


def _checkout(tmp_path: Path) -> Path:
    path = tmp_path / "checkout"
    path.mkdir()
    (path / "Example.java").write_text("class Example {}\n", encoding="utf-8")
    for args in (
        ["init"],
        ["add", "."],
        ["-c", "user.name=Test", "-c", "user.email=t@example.invalid", "commit", "-m", "f"],
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
    return path


def test_web_scan_without_consent_stores_false(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/scans",
        json={
            "repository_url": "https://example.test/shop",
            "ai_review": True,
            "provider_profile": "cloud-test",
        },
        headers=_csrf(client),
    )
    assert response.status_code == 200, response.text
    run_id = response.json()["run_id"]
    engine = create_engine(f"sqlite:///{tmp_path / 'consent.db'}")
    with engine.connect() as connection:
        from sqlalchemy import text

        spec = connection.execute(
            text("SELECT scan_spec_json FROM runs WHERE id = :id"), {"id": run_id}
        ).scalar_one()
    assert json.loads(spec)["configuration"]["allow_cloud_model"] is False


def test_web_scan_with_consent_stores_true(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    client = _client(tmp_path, monkeypatch)
    response = client.post(
        "/api/scans",
        json={
            "repository_url": "https://example.test/shop",
            "ai_review": True,
            "provider_profile": "cloud-test",
            "allow_cloud_model": True,
        },
        headers=_csrf(client),
    )
    assert response.status_code == 200, response.text
    run_id = response.json()["run_id"]
    engine = create_engine(f"sqlite:///{tmp_path / 'consent.db'}")
    with engine.connect() as connection:
        from sqlalchemy import text

        spec = connection.execute(
            text("SELECT scan_spec_json FROM runs WHERE id = :id"), {"id": run_id}
        ).scalar_one()
    assert json.loads(spec)["configuration"]["allow_cloud_model"] is True


def test_execute_without_consent_skips_model_stages(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    import vulnscan.providers.client as client_mod
    import vulnscan.providers.profile_store as store_mod
    import vulnscan.web.phase2_routes as routes
    from vulnscan.contracts.enums import ProviderProtocol
    from vulnscan.contracts.provider import ProviderProfile
    from vulnscan.storage.database import get_session
    from vulnscan.storage.models import TargetORM

    checkout = _checkout(tmp_path)
    db = str(tmp_path / "consent.db")
    engine = create_engine(f"sqlite:///{db}")
    migrate(engine)
    with get_session(db) as session:
        target = TargetORM(repository_url=str(checkout), commit_sha="0" * 40)
        session.add(target)
        session.flush()
        session.add(RunORM(target_id=target.id, public_id="web-consent1", status="queued"))

    def _no_client(*_args, **_kwargs):
        raise AssertionError("model called")

    monkeypatch.setattr(client_mod.ProviderClient, "__init__", _no_client)
    monkeypatch.setattr(
        store_mod,
        "load_profile",
        lambda _id: ProviderProfile(
            id="cloud-test",
            label="Cloud",
            protocol=ProviderProtocol.OPENAI_CHAT_COMPLETIONS,
            base_url="https://api.test.invalid/v1",
            api_key_env="TEST_KEY",
            models=["m"],
            default_model="m",
        ),
    )
    routes._execute_web_scan(
        db,
        str(tmp_path / "out"),
        "web-consent1",
        {
            "checkout": str(checkout),
            "repo": str(checkout),
            "profile": "fast",
            "ai_review": True,
            "provider_profile": "cloud-test",
            "mode": "deterministic",
            "tools": ["semgrep"],
        },
    )
    with get_session(db) as session:
        row = session.query(RunORM).filter_by(public_id="web-consent1").first()
        assert row is not None
        result = json.loads(row.result_json or "{}")
        stages = {e["stage"]: e for e in result["stages"]}
        assert stages["targeted_deep_analysis"]["status"] == "skipped"
        assert "--allow-cloud-model" in stages["targeted_deep_analysis"]["message"]
        assert FAKE_KEY not in json.dumps(result)
