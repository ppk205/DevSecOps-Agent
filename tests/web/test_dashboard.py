"""T06 dashboard: four screens, CSRF, escaped content, status updates, exports."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnscan.contracts.enums import CWECategory, FindingStatus, Severity, ToolName
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.storage.models import Base, FindingORM, RunORM, StageORM, TargetORM
from vulnscan.web.app import create_app


def _finding(
    title: str = "SQL injection", status: FindingStatus = FindingStatus.CONFIRMED
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id="f-1",
        run_id="run-1",
        fingerprint="fp-1",
        title=title,
        description="User input reaches a SQL query",
        cwe_category=CWECategory.SQL_INJECTION,
        severity=Severity.HIGH,
        status=status,
        observations=[
            Observation(
                observation_id="obs-1",
                detected_at=now,
                run_id="run-1",
                tool=ToolName.SEMGREP,
                tool_version="1.0.0",
                rule_id="java.sql.injection",
                cwe_category=CWECategory.SQL_INJECTION,
                severity=Severity.HIGH,
                message="Detected at LoginServlet.java:42",
                confidence=0.9,
                location=SourceCoordinate(
                    file_path="src/LoginServlet.java", line_start=42, line_end=43
                ),
            )
        ],
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        target = TargetORM(
            repository_url="https://github.com/example/bookstore", commit_sha="a" * 40
        )
        session.add(target)
        session.flush()
        run = RunORM(
            target_id=target.id,
            status="completed",
            scan_spec_json=json.dumps({"target_repository_url": target.repository_url}),
        )
        session.add(run)
        session.flush()
        session.add(
            StageORM(
                run_id=run.id,
                ordinal=0,
                name="scan",
                status="completed",
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
        )
        session.add(FindingORM(run_id=run.id, finding_json=_finding().model_dump_json()))
        session.commit()
        run_pk = run.id

    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    with TestClient(app) as test_client:
        test_client.run_pk = run_pk  # type: ignore[attr-defined]
        yield test_client


class TestFourScreens:
    def test_screen_one_target_registration(self, client: TestClient):
        response = client.get("/")
        assert response.status_code == 200
        assert "Target registration" in response.text
        assert 'name="target_repository_url"' in response.text
        assert 'name="_csrf"' in response.text

    def test_screen_two_run_progress(self, client: TestClient):
        response = client.get(f"/runs/{client.run_pk}")
        assert response.status_code == 200
        assert "Run progress" in response.text
        assert "Semgrep" in response.text or "scan" in response.text.lower()

    def test_screen_three_findings(self, client: TestClient):
        response = client.get(f"/runs/{client.run_pk}/findings")
        assert response.status_code == 200
        assert "Findings" in response.text
        assert "SQL injection" in response.text
        assert "Confirmed" in response.text

    def test_screen_four_evidence_detail(self, client: TestClient):
        response = client.get("/findings/f-1")
        assert response.status_code == 200
        assert "Evidence detail" in response.text
        assert "java.sql.injection" in response.text
        assert "LoginServlet.java" in response.text


class TestSecurity:
    def test_repository_content_is_escaped_in_finding_detail(self, tmp_path: Path):
        engine = create_engine(f"sqlite:///{tmp_path / 'xss.db'}")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        payload = "<script>alert('repo')</script>"
        with Session() as session:
            target = TargetORM(repository_url="x", commit_sha="b" * 40)
            session.add(target)
            session.flush()
            run = RunORM(target_id=target.id, status="completed")
            session.add(run)
            session.flush()
            session.add(
                FindingORM(
                    run_id=run.id,
                    finding_json=_finding(payload, FindingStatus.UNRESOLVED).model_dump_json(),
                )
            )
            session.commit()
        app = create_app(engine=engine, export_dir=tmp_path / "exports")
        response = TestClient(app).get("/findings/f-1")
        assert payload not in response.text
        assert "&lt;script&gt;" in response.text

    def test_state_change_requires_csrf(self, client: TestClient):
        response = client.post(
            "/findings/f-1/status",
            data={"status": "rejected"},
            follow_redirects=False,
        )
        assert response.status_code == 403

    def test_valid_csrf_allows_status_update(self, client: TestClient):
        home = client.get("/")
        token = home.cookies["vulnscan_csrf"]
        response = client.post(
            "/findings/f-1/status",
            data={"status": "rejected", "_csrf": token},
            follow_redirects=False,
        )
        assert response.status_code in (303, 302)
        detail = client.get("/findings/f-1")
        assert "Rejected" in detail.text


class TestExports:
    @pytest.mark.parametrize(
        "fmt,expected",
        [
            ("json", "application/json"),
            ("sarif", "application/sarif+json"),
            ("html", "text/html"),
            ("markdown", "text/markdown"),
        ],
    )
    def test_download_format(self, client: TestClient, fmt: str, expected: str):
        response = client.get(f"/runs/{client.run_pk}/export/{fmt}")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected)
        assert "Content-Disposition" in response.headers

    def test_json_export_preserves_counts(self, client: TestClient):
        response = client.get(f"/runs/{client.run_pk}/export/json")
        data = response.json()
        assert data["counts"]["confirmed"] == 1
        assert data["counts"]["unprocessed"] == 0


class TestApi:
    def test_run_json_api_redacts_nothing_but_returns_four_counts(self, client: TestClient):
        response = client.get(f"/api/runs/{client.run_pk}")
        assert response.status_code == 200
        counts = response.json()["counts"]
        assert set(counts) >= {"total", "confirmed", "rejected", "unresolved", "unprocessed"}
