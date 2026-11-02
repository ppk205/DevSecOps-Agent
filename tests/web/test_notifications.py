"""Task 4: notifications list/ack, fix .diff download, webhook best-effort."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnscan.storage.database import migrate
from vulnscan.storage.models import FixProposalORM, RunORM, TargetORM
from vulnscan.web.app import create_app

_DIFF = (
    "--- a/src/app.py\n+++ b/src/app.py\n"
    "@@ -8 +8 @@\n-    cur.execute(\"SELECT * FROM x\")\n+    cur.execute(\"SELECT * FROM x WHERE n = ?\", (n,))\n"
)


def _client(tmp_path: Path, monkeypatch, result_json: str = '{"gate": "failed"}') -> tuple[TestClient, int, int]:
    monkeypatch.chdir(tmp_path)
    engine = create_engine(f"sqlite:///{tmp_path / 'notif.db'}")
    migrate(engine)
    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    factory = sessionmaker(bind=engine)
    with factory() as session:
        target = TargetORM(repository_url="https://example.test/repo", commit_sha="a" * 40)
        session.add(target)
        session.flush()
        run = RunORM(target_id=target.id, status="completed", result_json=result_json)
        session.add(run)
        session.flush()
        proposal = FixProposalORM(
            run_id=run.id, finding_id="f1", diff_text=_DIFF, status="verified"
        )
        session.add(proposal)
        session.flush()
        rid, pid = run.id, proposal.id
        session.commit()
    return TestClient(app), rid, pid


def _csrf(client: TestClient) -> dict[str, str]:
    token = client.get("/api/health").cookies.get("vulnscan_csrf")
    assert token, "CSRF cookie missing"
    return {"X-CSRF-Token": token}


def test_list_creates_completion_notification_once(tmp_path: Path, monkeypatch) -> None:
    client, rid, _ = _client(tmp_path, monkeypatch)
    first = client.get("/api/notifications")
    assert first.status_code == 200
    body = first.json()
    assert body["unread"] == 2  # scan_completed + gate_failed (gate=failed)
    assert {n["kind"] for n in body["notifications"]} == {"scan_completed", "gate_failed"}
    assert all(n["run_id"] == rid for n in body["notifications"])
    second = client.get("/api/notifications")
    assert second.json()["unread"] == 2  # idempotent: no duplicates
    assert len(second.json()["notifications"]) == 2


def test_ack_marks_read_and_404_unknown(tmp_path: Path, monkeypatch) -> None:
    client, _, _ = _client(tmp_path, monkeypatch, result_json='{"gate": "pass"}')
    body = client.get("/api/notifications").json()
    assert body["unread"] == 1
    nid = body["notifications"][0]["id"]
    ack = client.post(f"/api/notifications/{nid}/ack", headers=_csrf(client))
    assert ack.status_code == 200
    assert ack.json()["is_read"] is True
    assert client.get("/api/notifications").json()["unread"] == 0
    missing = client.post("/api/notifications/9999/ack", headers=_csrf(client))
    assert missing.status_code == 404


def test_fix_diff_download(tmp_path: Path, monkeypatch) -> None:
    client, rid, pid = _client(tmp_path, monkeypatch)
    response = client.get(f"/api/scans/{rid}/fixes/{pid}/download")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "attachment" in response.headers["content-disposition"]
    assert response.text == _DIFF
    assert client.get(f"/api/scans/{rid}/fixes/9999/download").status_code == 404
    assert client.get(f"/api/scans/9999/fixes/{pid}/download").status_code == 404


def test_webhook_failure_never_breaks_listing(tmp_path: Path, monkeypatch) -> None:
    import urllib.request

    def _boom(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise ConnectionError("webhook down")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.setenv("WEBHOOK_URL", "http://127.0.0.1:9/hook")
    client, _, _ = _client(tmp_path, monkeypatch)  # gate=failed triggers dispatch
    body = client.get("/api/notifications")
    assert body.status_code == 200
    assert {n["kind"] for n in body.json()["notifications"]} >= {"gate_failed"}


def test_webhook_called_on_gate_fail(tmp_path: Path, monkeypatch) -> None:
    import urllib.request

    seen: dict[str, object] = {}

    class _FakeResponse:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *args: object) -> bool:
            return False

    def _capture(request, timeout=None):  # type: ignore[no-untyped-def]
        seen["url"] = request.full_url
        seen["payload"] = json.loads(request.data.decode("utf-8"))
        return _FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", _capture)
    monkeypatch.setenv("WEBHOOK_URL", "http://example.test/hook")
    client, rid, _ = _client(tmp_path, monkeypatch)
    assert client.get("/api/notifications").status_code == 200
    assert seen["url"] == "http://example.test/hook"
    assert seen["payload"] == {
        "run_id": rid,
        "kind": "gate_failed",
        "message": f"Scan #{rid} gate failed.",
    }
