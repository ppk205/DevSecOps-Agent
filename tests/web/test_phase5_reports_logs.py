"""Phase 5: scan reports, comparison, and derived logs.

Covers ``GET/POST /api/scans/{id}/reports``,
``GET /api/reports/{rid}/download`` (path validation + size cap),
``GET /api/compare`` (per-scanner/per-CWE tables + new/fixed/changed diff),
``GET /api/logs`` + ``GET /api/logs/stream`` (filters, derived granularity),
and the secret-leak test: a seeded fake key must never appear in any
log/event/report response.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnscan.contracts.enums import CWECategory, FindingStatus, Severity, ToolName
from vulnscan.contracts.finding import Finding, Observation, SourceCoordinate
from vulnscan.storage.database import migrate
from vulnscan.storage.models import (
    FindingORM,
    RunORM,
    ScanEventORM,
    StageORM,
    TargetORM,
)
from vulnscan.web.app import create_app

FAKE_KEY = "sk-FAKEKEY1234567890abcdef"
FAKE_TOKEN_LINE = f"scan failed: api_key={FAKE_KEY} rejected by provider"


def _finding(
    finding_id: str,
    run_id: str,
    title: str,
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.UNPROCESSED,
    tool: ToolName = ToolName.SEMGREP,
    cwe: CWECategory = CWECategory.SQL_INJECTION,
) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id=finding_id,
        run_id=run_id,
        fingerprint=f"fp-{finding_id}",
        title=title,
        cwe_category=cwe,
        severity=severity,
        status=status,
        observations=[
            Observation(
                observation_id=f"obs-{finding_id}",
                run_id=run_id,
                tool=tool,
                tool_version="1.0",
                rule_id="rule-1",
                rule_pack_version="1.0",
                cwe_category=cwe,
                severity=severity,
                message=title,
                location=SourceCoordinate(
                    file_path="src/main/java/com/bookstore/dao/BookDao.java",
                    line_start=42,
                ),
                detected_at=now,
            )
        ],
        created_at=now,
        updated_at=now,
    )


def _seeded_client(tmp_path: Path) -> TestClient:
    engine = create_engine(f"sqlite:///{tmp_path / 'phase5.db'}")
    migrate(engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        target = TargetORM(repository_url="https://example.test/repo", commit_sha="c" * 40)
        session.add(target)
        session.flush()
        run1 = RunORM(target_id=target.id, status="completed")
        run2 = RunORM(target_id=target.id, status="completed")
        session.add_all([run1, run2])
        session.flush()
        for ordinal, name in enumerate(["scan", "report"]):
            session.add(
                StageORM(
                    run_id=run1.id,
                    ordinal=ordinal,
                    name=name,
                    status="completed",
                    started_at=datetime.now(UTC),
                    completed_at=datetime.now(UTC),
                )
            )
        session.add(
            StageORM(
                run_id=run2.id,
                ordinal=0,
                name="scan",
                status="completed",
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
        )
        session.add_all(
            [
                FindingORM(
                    run_id=run1.id,
                    finding_id="f-shared",
                    finding_json=_finding("f-shared", "1", "Shared issue").model_dump_json(),
                    summary_json="{}",
                ),
                FindingORM(
                    run_id=run1.id,
                    finding_id="f-fixed",
                    finding_json=_finding("f-fixed", "1", "Old issue").model_dump_json(),
                    summary_json="{}",
                ),
                FindingORM(
                    run_id=run2.id,
                    finding_id="f-shared",
                    finding_json=_finding(
                        "f-shared",
                        "2",
                        "Shared issue",
                        severity=Severity.CRITICAL,
                    ).model_dump_json(),
                    summary_json="{}",
                ),
                FindingORM(
                    run_id=run2.id,
                    finding_id="f-new",
                    finding_json=_finding("f-new", "2", "Fresh issue").model_dump_json(),
                    summary_json="{}",
                ),
            ]
        )
        session.add(
            ScanEventORM(
                run_id=run1.id,
                seq=0,
                kind="log",
                stage="scan",
                message=FAKE_TOKEN_LINE,
                payload_json='{"note": "retrying"}',
                created_at=datetime.now(UTC),
            )
        )
        session.add(
            ScanEventORM(
                run_id=run1.id,
                seq=1,
                kind="ai_step",
                stage="hunt",
                message="hunt verdict: reachable sink",
                payload_json=f'{{"finding_id": "f-shared", "key": "{FAKE_KEY}"}}',
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
        run1_pk, run2_pk = run1.id, run2.id
    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    with TestClient(app) as test_client:
        test_client.run1 = run1_pk
        test_client.run2 = run2_pk
        return test_client


def _post_report(client: TestClient, run_id: int, fmt: str) -> Any:
    """POST one report generation with a valid CSRF token (middleware enforced)."""
    home = client.get("/api/health")
    token = home.cookies["vulnscan_csrf"]
    return client.post(
        f"/api/scans/{run_id}/reports",
        json={"format": fmt},
        headers={"X-CSRF-Token": token},
    )


class TestReports:
    def test_reports_list_flags_ungenerated(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get(f"/api/scans/{client.run1}/reports")
        assert response.status_code == 200
        body = response.json()
        assert {report["format"] for report in body["reports"]} == {
            "json",
            "sarif",
            "html",
            "markdown",
            "txt",
            "docx",
            "csv",
        }
        assert all(report["generated"] is False for report in body["reports"])
        assert response.headers["X-Contract-Version"] == "1"

    def test_generate_then_download_csv(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        created = _post_report(client, client.run1, "csv")
        assert created.status_code == 201
        assert created.json()["generated"] is True
        listed = client.get(f"/api/scans/{client.run1}/reports").json()
        csv_entry = next(r for r in listed["reports"] if r["format"] == "csv")
        assert csv_entry["generated"] is True
        assert csv_entry["size_bytes"] and csv_entry["size_bytes"] > 0
        assert csv_entry["download_url"] is not None
        download = client.get(csv_entry["download_url"])
        assert download.status_code == 200
        assert download.headers["content-type"] == "text/csv; charset=utf-8"
        first_line = download.text.splitlines()[0]
        assert first_line == "finding_id,title,severity,status,tools,file,line,cwe"
        assert "f-shared" in download.text

    def test_generate_rejects_unknown_format(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = _post_report(client, client.run1, "pdf")
        assert response.status_code == 422

    def test_download_rejects_traversal(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        assert client.get("/api/reports/../app/download").status_code in {400, 404}
        assert client.get("/api/reports/run-1-csv..../download").status_code == 400
        assert client.get("/api/reports/run-1-pdf.pdf/download").status_code == 400
        assert client.get("/api/reports/run-9-csv.csv/download").status_code == 404


class TestCompare:
    def test_compare_tables_and_diff(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get(f"/api/compare?scan_ids={client.run1},{client.run2}")
        assert response.status_code == 200
        body = response.json()
        assert body["baseline"] == client.run1
        assert [scan["total"] for scan in body["scans"]] == [2, 2]
        scanner_tools = {row["tool"] for row in body["by_scanner"]}
        assert "semgrep" in scanner_tools
        assert {entry["finding_id"] for entry in body["new"]} == {"f-new"}
        assert {entry["finding_id"] for entry in body["fixed"]} == {"f-fixed"}
        assert {entry["finding_id"] for entry in body["changed"]} == {"f-shared"}

    def test_compare_requires_two_scans(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        assert client.get(f"/api/compare?scan_ids={client.run1}").status_code == 422
        assert client.get("/api/compare?scan_ids=nope").status_code == 422

    def test_compare_html_export(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get(f"/api/compare?scan_ids={client.run1},{client.run2}&export=html")
        assert response.status_code == 200
        assert "Scan comparison" in response.text
        assert "f-new" in response.text


class TestLogs:
    def test_logs_derive_from_stages_and_events(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get(f"/api/logs?scan_id={client.run1}")
        assert response.status_code == 200
        body = response.json()
        assert body["redacted"] is True
        assert "Coarse granularity" in body["granularity"]
        sources = {line["source"] for line in body["lines"]}
        assert {"scan", "report", "hunt"} <= sources
        assert all("seq" in line for line in body["lines"])

    def test_logs_filters(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        debug = client.get(f"/api/logs?scan_id={client.run1}&level=debug").json()
        assert debug["lines"]
        assert all(line["level"] == "debug" for line in debug["lines"])
        hunt = client.get(f"/api/logs?scan_id={client.run1}&source=hunt").json()
        assert hunt["lines"]
        assert all(line["source"] == "hunt" for line in hunt["lines"])
        assert client.get("/api/logs?scan_id=1&level=bogus").status_code == 422

    def test_logs_stream_replays_without_secret(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        with client.stream("GET", f"/api/logs/stream?scan_id={client.run1}") as response:
            assert response.status_code == 200
            body = response.read().decode()
        assert "event: hello" in body
        assert "event: live" in body
        assert FAKE_KEY not in body


class TestCsrfToken:
    def test_csrf_endpoint_issues_token_for_spa_posts(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get("/api/csrf")
        assert response.status_code == 200
        assert response.headers["X-Contract-Version"] == "1"
        token = response.json()["csrf_token"]
        assert isinstance(token, str) and len(token) > 16
        created = client.post(
            f"/api/scans/{client.run1}/reports",
            json={"format": "txt"},
            headers={"X-CSRF-Token": token},
        )
        assert created.status_code == 201


class TestSecretLeak:
    def test_fake_key_never_leaves_the_api(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        run_id = client.run1
        tainted = [
            client.get(f"/api/logs?scan_id={run_id}").text,
            client.get(f"/api/scans/{run_id}/events/history").text,
        ]
        with client.stream("GET", f"/api/logs/stream?scan_id={run_id}") as stream:
            tainted.append(stream.read().decode())
        with client.stream("GET", f"/api/scans/{run_id}/events") as stream:
            tainted.append(stream.read().decode())
        clean = [
            client.get(f"/api/scans/{run_id}/reports").text,
            client.get(f"/api/compare?scan_ids={run_id},{client.run2}").text,
        ]
        for payload in tainted + clean:
            assert FAKE_KEY not in payload
        # Responses carrying the tainted lines must show the redaction marker.
        for payload in tainted:
            assert "***REDACTED***" in payload
