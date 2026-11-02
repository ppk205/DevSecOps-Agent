"""Phase 4 findings: filtered list + full detail JSON endpoints.

Covers GET /api/scans/{id}/findings (filters, sort, pagination) and
GET /api/findings/{id} (evidence, AI assessment, verification table).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnscan.storage.database import migrate
from vulnscan.storage.models import FindingORM, RunORM, TargetORM
from vulnscan.web.app import create_app


def _obs(
    tool: str,
    rule: str,
    severity: str,
    message: str,
    file: str,
    line: int,
    dependency: str | None = None,
) -> dict[str, Any]:
    obs: dict[str, Any] = {
        "tool": tool,
        "rule_id": rule,
        "severity": severity,
        "message": message,
        "location": {
            "file_path": file,
            "line_start": line,
            "snippet": f"// {rule} evidence\nvulnerable_call({line});",
        },
    }
    if dependency is not None:
        obs["dependency_identity"] = dependency
    return obs


def _finding(
    fid: str,
    title: str,
    severity: str,
    status: str,
    cwe: str,
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "finding_id": fid,
        "severity": severity,
        "status": status,
        "cwe_category": cwe,
        "title": title,
        "description": f"{title} description",
        "observations": observations,
    }


def _seeded_client(tmp_path: Path) -> TestClient:
    engine = create_engine(f"sqlite:///{tmp_path / 'phase4.db'}")
    migrate(engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        target = TargetORM(repository_url="https://example.test/repo", commit_sha="c" * 40)
        session.add(target)
        session.flush()
        run = RunORM(
            target_id=target.id,
            status="completed",
            result_json=json.dumps(
                {
                    "assessments": [
                        {
                            "finding_id": "F-001",
                            "proposed_severity": "critical",
                            "proposed_status": "confirmed",
                            "cvss": {
                                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
                                "base_score": 9.3,
                                "qualitative": "critical",
                                "notes": "network reachable, no auth",
                            },
                            "confidence": 0.9,
                            "assumptions": ["attacker reaches /search unauthenticated"],
                            "rationale": "tainted flow into query builder",
                        },
                        {
                            "finding_id": "F-003",
                            "proposed_severity": "medium",
                            "proposed_status": "unresolved",
                            "confidence": 0.4,
                            "assumptions": [],
                            "rationale": "weak signal",
                        },
                    ],
                    "validation_decisions": [
                        {
                            "finding_id": "F-001",
                            "outcome": "demonstrated",
                            "previous_status": "unprocessed",
                            "new_status": "confirmed",
                        }
                    ],
                    "laya_verification": [
                        {
                            "finding_id": "F-001",
                            "procedure_version": "laya-01/sql-injection",
                            "outcome": "demonstrated",
                        }
                    ],
                }
            ),
        )
        session.add(run)
        session.flush()
        findings = [
            _finding(
                "F-001",
                "SQL injection in repository query",
                "high",
                "confirmed",
                "CWE-89",
                [_obs("semgrep", "java/sql-injection", "high", "tainted SQL", "Dao.java", 42)],
            ),
            _finding(
                "F-002",
                "Vulnerable dependency: log4j-core",
                "critical",
                "unprocessed",
                "CWE-1104",
                [
                    _obs(
                        "owasp-dependency-check",
                        "CVE-2021-44228",
                        "critical",
                        "log4shell",
                        "pom.xml",
                        10,
                        dependency="org.apache.logging.log4j:log4j-core:2.14.0",
                    )
                ],
            ),
            _finding(
                "F-003",
                "Cookie without Secure flag",
                "medium",
                "unresolved",
                "CWE-614",
                [_obs("semgrep", "cookie-secure", "medium", "missing flag", "Filter.java", 7)],
            ),
            _finding(
                "F-004",
                "Verbose stack trace on error page",
                "low",
                "rejected",
                "CWE-209",
                [_obs("spotbugs", "STACK_TRACE", "low", "stack trace", "error.jsp", 3)],
            ),
        ]
        for item in findings:
            session.add(FindingORM(run_id=run.id, finding_json=json.dumps(item)))
        session.commit()
        run_pk = run.id
    app = create_app(engine=engine, export_dir=tmp_path / "exports")
    with TestClient(app) as test_client:
        test_client.run_pk = run_pk  # type: ignore[attr-defined]
        return test_client


class TestScanFindingsList:
    def test_list_returns_all_with_contract_header(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get(f"/api/scans/{client.run_pk}/findings")
        assert response.status_code == 200
        assert response.headers["X-Contract-Version"] == "1"
        body = response.json()
        assert body["total"] == 4
        assert body["page"] == 1
        ids = [item["id"] for item in body["items"]]
        # Default sort is severity rank: critical first.
        assert ids[0] == "F-002"
        first = body["items"][0]
        assert first["origin"] == "dependency"
        assert first["scanners"] == ["owasp-dependency-check"]
        assert first["file"] == "pom.xml"

    def test_ai_changed_projection(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        body = client.get(f"/api/scans/{client.run_pk}/findings").json()
        by_id = {item["id"]: item for item in body["items"]}
        # Scanner said high, AI proposed critical.
        assert by_id["F-001"]["ai_severity"] == "critical"
        assert by_id["F-001"]["ai_changed"] is True
        # F-003 assessed at same severity as scanner: unchanged.
        assert by_id["F-003"]["ai_changed"] is False
        # No assessment recorded for F-002.
        assert by_id["F-002"]["ai_severity"] is None

    def test_severity_filter(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        body = client.get(f"/api/scans/{client.run_pk}/findings?severity=low,medium").json()
        assert body["total"] == 2
        assert {item["id"] for item in body["items"]} == {"F-003", "F-004"}

    def test_cwe_digits_filter(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        body = client.get(f"/api/scans/{client.run_pk}/findings?cwe=89").json()
        assert body["total"] == 1
        assert body["items"][0]["id"] == "F-001"

    def test_scanner_filter(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        body = client.get(f"/api/scans/{client.run_pk}/findings?scanner=spotbugs").json()
        assert body["total"] == 1
        assert body["items"][0]["id"] == "F-004"

    def test_verification_filter(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        body = client.get(
            f"/api/scans/{client.run_pk}/findings?verification=confirmed,rejected"
        ).json()
        assert {item["id"] for item in body["items"]} == {"F-001", "F-004"}

    def test_origin_and_ai_changed_filters(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        dep = client.get(f"/api/scans/{client.run_pk}/findings?origin=dependency").json()
        assert dep["total"] == 1 and dep["items"][0]["id"] == "F-002"
        changed = client.get(f"/api/scans/{client.run_pk}/findings?ai_changed=true").json()
        assert changed["total"] == 1 and changed["items"][0]["id"] == "F-001"

    def test_search_and_sort_and_pagination(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        search = client.get(f"/api/scans/{client.run_pk}/findings?q=cookie").json()
        assert search["total"] == 1 and search["items"][0]["id"] == "F-003"
        by_title = client.get(
            f"/api/scans/{client.run_pk}/findings?sort=title&order=desc&page=1&page_size=2"
        ).json()
        assert by_title["total"] == 4 and len(by_title["items"]) == 2
        page2 = client.get(f"/api/scans/{client.run_pk}/findings?page=2&page_size=3").json()
        assert page2["page"] == 2 and len(page2["items"]) == 1

    def test_bad_origin_and_unknown_run(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        assert client.get(f"/api/scans/{client.run_pk}/findings?origin=binary").status_code == 422
        assert client.get("/api/scans/9999/findings").status_code == 404


class TestFindingDetail:
    def test_detail_shape(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        response = client.get("/api/findings/F-001")
        assert response.status_code == 200
        assert response.headers["X-Contract-Version"] == "1"
        body = response.json()
        assert body["id"] == "F-001"
        assert body["scanner_severity"] == "high"
        assert body["ai"] is not None
        assert body["ai"]["cvss"]["vector"].startswith("CVSS:4.0/")
        assert body["ai"]["assumptions"] == ["attacker reaches /search unauthenticated"]
        assert body["verification"]["decision"]["new_status"] == "confirmed"
        assert body["verification"]["checks"][0]["outcome"] == "demonstrated"
        assert body["code"]["blocks"][0]["file"] == "Dao.java"
        assert body["code"]["taint_path"][0]["line"] == 42
        assert body["observations"][0]["rule_id"] == "java/sql-injection"
        assert body["raw"]["finding_id"] == "F-001"

    def test_detail_without_assessment(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        body = client.get("/api/findings/F-002").json()
        assert body["ai"] is None
        assert body["verification"]["decision"] is None
        assert body["verification"]["checks"][0]["outcome"] == "not_verified"

    def test_detail_scoped_to_run(self, tmp_path: Path) -> None:
        client = _seeded_client(tmp_path)
        assert client.get(f"/api/findings/F-001?run_id={client.run_pk}").status_code == 200
        assert client.get("/api/findings/F-001?run_id=9999").status_code == 404
        assert client.get("/api/findings/NOPE").status_code == 404
