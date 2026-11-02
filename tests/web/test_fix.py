"""AI fix endpoints: propose (mocked model), list, apply+verify on overlay."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine

from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile
from vulnscan.providers.profile_store import save_profile
from vulnscan.storage.database import get_session, migrate
from vulnscan.storage.models import FindingORM, FixProposalORM, RunORM, TargetORM
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
                        "snippet": 'cur.execute("SELECT * FROM x WHERE n = \'" + n + "\'")',
                    },
                }
            ],
        }
    )


def _client(tmp_path: Path, monkeypatch) -> tuple[TestClient, int]:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    for profile_id, url in (
        ("opencode-free", "https://cloud.invalid/v1"),
        ("other-cloud", "https://other.invalid/v1"),
        ("local", "http://127.0.0.1:1234/v1"),
    ):
        save_profile(
            ProviderProfile(
                id=profile_id,
                label=profile_id,
                protocol=ProviderProtocol.OPENAI_COMPATIBLE,
                base_url=url,
                api_key_env="",
                default_model="test-model",
            )
        )
    engine = create_engine(f"sqlite:///{tmp_path / 'fix.db'}")
    migrate(engine)
    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    with get_session(str(tmp_path / "fix.db")) as session:
        target = TargetORM(repository_url="local", commit_sha="0" * 40)
        session.add(target)
        session.flush()
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

    def fake_propose(finding, profile_id, model=None, max_tokens=2000, **kwargs):
        assert profile_id == "opencode-free"
        assert "code_context" in kwargs
        return fixmod.FixProposal(
            finding_id=finding["finding_id"],
            file_path="src/app.py",
            diff_text=(
                "--- a/src/app.py\n+++ b/src/app.py\n"
                "@@ -8 +8 @@\n"
                '-    cur.execute("SELECT * FROM x WHERE n = \'" + n + "\'")\n'
                '+    cur.execute("SELECT * FROM x WHERE n = ?", (n,))\n'
            ),
            model="iceman-contributor-free",
        )

    monkeypatch.setattr(fixmod, "propose_fix", fake_propose)
    client, rid = _client(tmp_path, monkeypatch)
    headers = _csrf(client)

    # Queue proposals for all findings.
    queued = client.post(
        f"/api/scans/{rid}/fix",
        json={
            "provider_profile": "opencode-free",
            "provider_model": "iceman-contributor-free",
            "allow_cloud_model": True,
        },
        headers=headers,
    )
    assert queued.status_code == 202, queued.text
    assert queued.json()["accepted"] == 2

    listed = client.get(f"/api/scans/{rid}/fixes").json()
    assert len(listed["proposals"]) == 2
    assert all(p["status"] == "proposed" for p in listed["proposals"])
    assert "SELECT * FROM x WHERE n = ?" in listed["proposals"][0]["diff"]

    # Re-queue skips already-proposed rows (no duplicates).
    client.post(
        f"/api/scans/{rid}/fix",
        json={"provider_profile": "opencode-free", "allow_cloud_model": True},
        headers=headers,
    )
    assert len(client.get(f"/api/scans/{rid}/fixes").json()["proposals"]) == 2

    # Apply needs a local checkout; this run has none -> honest 422.
    pid = listed["proposals"][0]["id"]
    denied = client.post(f"/api/scans/{rid}/fixes/{pid}/apply", headers=headers)
    assert denied.status_code == 422


@pytest.mark.parametrize(
    ("configured", "run_consent", "override", "explicit", "allowed"),
    [
        ("opencode-free", False, None, None, False),
        ("opencode-free", True, None, None, True),
        ("opencode-free", True, "other-cloud", None, False),
        ("opencode-free", True, "opencode-free", None, True),
        ("opencode-free", False, "other-cloud", True, True),
        ("opencode-free", True, None, False, False),
        ("local", False, None, None, True),
        ("opencode-free", True, "local", None, True),
    ],
)
def test_fix_consent_follows_selected_provider(
    tmp_path, monkeypatch, configured, run_consent, override, explicit, allowed
):
    import vulnscan.ai.fix as fixmod

    client, rid = _client(tmp_path, monkeypatch)
    with get_session(str(tmp_path / "fix.db")) as session:
        run = session.get(RunORM, rid)
        run.scan_spec_json = json.dumps(
            {"configuration": {"provider_profile": configured, "allow_cloud_model": run_consent}}
        )
    calls = []

    def fake_propose(finding, profile_id, model=None, **kwargs):
        calls.append((profile_id, kwargs.get("allow_cloud_model")))
        return fixmod.FixProposal(finding["finding_id"], "src/app.py", "diff", "test-model")

    monkeypatch.setattr(fixmod, "propose_fix", fake_propose)
    body = {}
    if override is not None:
        body["provider_profile"] = override
    if explicit is not None:
        body["allow_cloud_model"] = explicit
    response = client.post(f"/api/scans/{rid}/fix", json=body, headers=_csrf(client))
    assert response.status_code == (202 if allowed else 422), response.text
    assert bool(calls) is allowed
    if allowed:
        assert all(isinstance(consent, bool) for _, consent in calls)
    else:
        assert "allow-cloud-model" in response.text


@pytest.mark.parametrize("path_kind", ["absolute", "backslash", "symlink"])
def test_fix_context_never_reads_outside_checkout(tmp_path, monkeypatch, path_kind):
    import vulnscan.ai.fix as fixmod

    client, rid = _client(tmp_path, monkeypatch)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("OUTSIDE-CONTENT")
    if path_kind == "absolute":
        path = str(outside)
    elif path_kind == "backslash":
        path = r"..\outside.py"
    else:
        try:
            (checkout / "alias.py").symlink_to(outside)
        except OSError as exc:
            pytest.skip(f"Symlinks unavailable: {exc}")
        path = "alias.py"
    with get_session(str(tmp_path / "fix.db")) as session:
        run = session.get(RunORM, rid)
        run.target.repository_url = str(checkout)
        for row in session.query(FindingORM).filter_by(run_id=rid):
            finding = json.loads(row.finding_json)
            finding["observations"][0]["location"]["file_path"] = path
            row.finding_json = json.dumps(finding)
    contexts = []

    def fake_propose(finding, profile_id, model=None, **kwargs):
        contexts.append(kwargs["code_context"])
        return fixmod.FixProposal(finding["finding_id"], path, "diff", "test-model")

    monkeypatch.setattr(fixmod, "propose_fix", fake_propose)
    response = client.post(
        f"/api/scans/{rid}/fix", json={"provider_profile": "local"}, headers=_csrf(client)
    )
    assert response.status_code == 202
    assert contexts == ["", ""]


def test_fix_failures_are_redacted_before_storage_and_api(tmp_path, monkeypatch):
    import vulnscan.ai.fix as fixmod

    client, rid = _client(tmp_path, monkeypatch)
    secret = "sk-" + "x" * 30  # Synthetic key-shaped fixture.

    def fake_propose(*args, **kwargs):
        raise ValueError(secret)

    monkeypatch.setattr(fixmod, "propose_fix", fake_propose)
    response = client.post(
        f"/api/scans/{rid}/fix", json={"provider_profile": "local"}, headers=_csrf(client)
    )
    assert response.status_code == 202
    with get_session(str(tmp_path / "fix.db")) as session:
        assert all(secret not in row.error for row in session.query(FixProposalORM))
    listed = client.get(f"/api/scans/{rid}/fixes")
    assert secret not in listed.text
    assert "[REDACTED]" in listed.text


def test_fix_list_redacts_existing_nested_proposals(tmp_path, monkeypatch):
    client, rid = _client(tmp_path, monkeypatch)
    secret = "sk-" + "x" * 30
    with get_session(str(tmp_path / "fix.db")) as session:
        session.add(
            FixProposalORM(
                run_id=rid,
                finding_id="f1",
                diff_text=secret,
                model=secret,
                status="failed",
                error=secret,
                verification_json=json.dumps({"detail": secret, "nested": [secret]}),
            )
        )
    listed = client.get(f"/api/scans/{rid}/fixes")
    assert listed.status_code == 200
    assert secret not in listed.text


@pytest.mark.parametrize("scanner_error", [False, True])
def test_apply_verifies_only_overlay_and_preserves_finding_status(
    tmp_path, monkeypatch, scanner_error
):
    import vulnscan.ai.fix as fixmod

    client, rid = _client(tmp_path, monkeypatch)
    checkout = tmp_path / "checkout"
    (checkout / "src").mkdir(parents=True)
    original = checkout / "src" / "app.py"
    original.write_text("old\n")
    with get_session(str(tmp_path / "fix.db")) as session:
        run = session.get(RunORM, rid)
        run.target.repository_url = str(checkout)
        proposal = FixProposalORM(
            run_id=rid,
            finding_id="f1",
            diff_text="--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-old\n+new\n",
            model="test-model",
            status="proposed",
        )
        session.add(proposal)
        session.flush()
        pid = proposal.id
        finding_before = (
            session.query(FindingORM).filter_by(run_id=rid, finding_id="f1").one().finding_json
        )

    def scanner(args, **kwargs):
        path = Path(args[-1])
        assert path != original
        assert path.read_text() == "new\n"
        return SimpleNamespace(
            returncode=2 if scanner_error else 0,
            stdout=json.dumps({"results": [], "errors": [], "paths": {"scanned": [str(path)]}}),
        )

    monkeypatch.setattr(fixmod.subprocess, "run", scanner)
    response = client.post(f"/api/scans/{rid}/fixes/{pid}/apply", headers=_csrf(client))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == ("failed" if scanner_error else "verified")
    assert response.json()["verification"]["fixed"] is not scanner_error
    assert original.read_text() == "old\n"
    with get_session(str(tmp_path / "fix.db")) as session:
        assert (
            session.query(FindingORM).filter_by(run_id=rid, finding_id="f1").one().finding_json
            == finding_before
        )


def test_apply_failure_is_redacted_in_storage_and_response(tmp_path, monkeypatch):
    import vulnscan.ai.fix as fixmod

    client, rid = _client(tmp_path, monkeypatch)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    secret = "sk-" + "x" * 30
    with get_session(str(tmp_path / "fix.db")) as session:
        session.get(RunORM, rid).target.repository_url = str(checkout)
        row = FixProposalORM(run_id=rid, finding_id="f1", diff_text="diff", status="proposed")
        session.add(row)
        session.flush()
        pid = row.id

    def failure(*args, **kwargs):
        raise ValueError(secret)

    monkeypatch.setattr(fixmod, "prepare_overlay", failure)
    response = client.post(f"/api/scans/{rid}/fixes/{pid}/apply", headers=_csrf(client))
    assert response.status_code == 422
    assert secret not in response.text
    assert "[REDACTED]" in response.text
    with get_session(str(tmp_path / "fix.db")) as session:
        row = session.get(FixProposalORM, pid)
        assert secret not in row.error
        assert secret not in row.verification_json
