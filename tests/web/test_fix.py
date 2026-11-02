"""AI fix endpoints: propose (mocked model), list, apply+verify on overlay."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from vulnscan.storage.database import get_session, migrate
from vulnscan.storage.models import FindingORM, TargetORM
from vulnscan.web.app import create_app


def _finding_json(fid: str) -> str:
    return json.dumps(
        {
            "finding_id": fid,
            "title": "CWE-89 at src/app.py:8",
            "severity": "high",
            "cwe_category": "CWE-89",
            "observations": [
                {
                    "rule_id": "py-sql-injection",
                    "location": {
                        "file_path": "src/app.py",
                        "line_start": 8,
                        "snippet": "cur.execute(\"SELECT * FROM x WHERE n = '\" + n + \"'\")",
                    },
                }
            ],
        }
    )


def _client(tmp_path: Path, monkeypatch) -> tuple[TestClient, int]:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    engine = create_engine(f"sqlite:///{tmp_path / 'fix.db'}")
    migrate(engine)
    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    with get_session(str(tmp_path / "fix.db")) as session:
        target = TargetORM(repository_url="local", commit_sha="0" * 40)
        session.add(target)
        session.flush()
        from vulnscan.storage.models import RunORM

        run = RunORM(target_id=target.id, status="completed")
        session.add(run)
        session.flush()
        session.add(FindingORM(run_id=run.id, finding_id="f1", finding_json=_finding_json("f1")))
        session.add(FindingORM(run_id=run.id, finding_id="f2", finding_json=_finding_json("f2")))
        session.flush()
        rid = run.id
    client = TestClient(app)
    return client, rid


def _csrf(client: TestClient) -> dict[str, str]:
    token = client.get("/api/health").cookies.get("vulnscan_csrf")
    assert token, "CSRF cookie missing"
    return {"X-CSRF-Token": token}


def test_fix_flow_propose_list_apply(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import vulnscan.ai.fix as fixmod

    def fake_propose(finding, profile_id, model=None, max_tokens=2000):
        assert profile_id == "opencode-free"
        return fixmod.FixProposal(
            finding_id=finding["finding_id"],
            file_path="src/app.py",
            diff_text=(
                "--- a/src/app.py\n+++ b/src/app.py\n"
                "@@ -8 +8 @@\n"
                "-    cur.execute(\"SELECT * FROM x WHERE n = '\" + n + \"'\")\n"
                "+    cur.execute(\"SELECT * FROM x WHERE n = ?\", (n,))\n"
            ),
            model="iceman-contributor-free",
        )

    monkeypatch.setattr(fixmod, "propose_fix", fake_propose)
    client, rid = _client(tmp_path, monkeypatch)
    headers = _csrf(client)

    # Queue proposals for all findings.
    queued = client.post(
        f"/api/scans/{rid}/fix",
        json={"provider_profile": "opencode-free", "provider_model": "iceman-contributor-free"},
        headers=headers,
    )
    assert queued.status_code == 202, queued.text
    assert queued.json()["accepted"] == 2

    listed = client.get(f"/api/scans/{rid}/fixes").json()
    assert len(listed["proposals"]) == 2
    assert all(p["status"] == "proposed" for p in listed["proposals"])
    assert "SELECT * FROM x WHERE n = ?" in listed["proposals"][0]["diff"]

    # Re-queue skips already-proposed rows (no duplicates).
    client.post(f"/api/scans/{rid}/fix", json={"provider_profile": "opencode-free"}, headers=headers)
    assert len(client.get(f"/api/scans/{rid}/fixes").json()["proposals"]) == 2

    # Apply needs a local checkout; this run has none -> honest 422.
    pid = listed["proposals"][0]["id"]
    denied = client.post(f"/api/scans/{rid}/fixes/{pid}/apply", headers=headers)
    assert denied.status_code == 422
