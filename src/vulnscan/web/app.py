"""FastAPI dashboard for scan intake, progress, findings, and evidence.

LEGACY NOTE (Phase 1): the Jinja pages below (``/``, ``/runs/*``,
``/findings/*``) are the legacy server-rendered UI and stay working.
The new React SPA ("PIT WALL") is served at ``/app/*`` with an SPA
fallback once ``web-ui/dist`` has been built (see static mount at the
bottom of :func:`create_app`). New JSON surface lives under ``/api``.
"""

import csv
import hmac
import io
import json
import logging
import re
import secrets
from collections.abc import AsyncIterator, Generator
from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker
from sse_starlette.sse import EventSourceResponse

from vulnscan.contracts.enums import ExportFormat, FindingStatus
from vulnscan.contracts.finding import Finding
from vulnscan.core.config import ScanConfig
from vulnscan.core.finding_view import project_finding
from vulnscan.core.scan_service import ScanService
from vulnscan.reporting.reporter import ReportGenerator
from vulnscan.storage.database import get_engine, migrate
from vulnscan.storage.models import FindingORM, RunORM, ScanEventORM, StageORM
from vulnscan.version import APP_VERSION

_TEMPLATES = Path(__file__).with_name("templates")
_MIME = {
    ExportFormat.SARIF: "application/sarif+json",
    ExportFormat.JSON: "application/json",
    ExportFormat.HTML: "text/html",
    ExportFormat.MARKDOWN: "text/markdown",
}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
logger = logging.getLogger(__name__)


def _findings_for_run(session: Session, run_pk: int) -> list[Finding]:
    rows = (
        session.query(FindingORM).filter(FindingORM.run_id == run_pk).order_by(FindingORM.id).all()
    )
    return [Finding.model_validate_json(row.finding_json) for row in rows]


# ---- Phase 5 shared helpers: secret redaction + flat CSV -------------------
# Secret redaction runs on BOTH sides: the server redacts every log/event
# payload before it leaves the API, and the SPA redacts again before render
# (see web-ui/src/utils/redact.ts). The patterns below mirror the client.

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-[A-Za-z0-9]{8,}"), "sk-***REDACTED***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "***REDACTED***"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{8,}"), "***REDACTED***"),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"]?([^\s'\",;}]+)"
        ),
        r"\1=***REDACTED***",
    ),
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer ***REDACTED***"),
]


def redact_secrets(text: str) -> str:
    """Redact likely secret material from a log/event string (server-side)."""
    redacted = text
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_value(value: Any) -> Any:
    """Recursively redact strings inside a JSON-like payload."""
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value


def findings_csv(findings: list[Finding]) -> str:
    """Flat CSV renderer for findings (Phase 5 decision: implemented).

    Columns: finding_id,title,severity,status,tools,file,line,cwe. Tools are
    pipe-joined; file/line come from the first observation when present.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["finding_id", "title", "severity", "status", "tools", "file", "line", "cwe"])
    for finding in findings:
        data = finding.model_dump(mode="json")
        observations = data.get("observations") or []
        first = observations[0] if observations else {}
        location = first.get("location", {}) if isinstance(first, dict) else {}
        tools = [obs.get("tool") for obs in observations if isinstance(obs, dict)]
        tools = [str(tool) for tool in tools if tool]
        writer.writerow(
            [
                data.get("finding_id", ""),
                data.get("title", ""),
                str(data.get("severity", "")),
                str(data.get("status", "")),
                "|".join(str(tool) for tool in tools),
                location.get("file_path", "") if isinstance(location, dict) else "",
                location.get("line_start", "") if isinstance(location, dict) else "",
                str(data.get("cwe_category", "")),
            ]
        )
    return buffer.getvalue()


def create_app(
    engine: Engine | None = None,
    export_dir: str | Path = "artifacts/reports",
) -> FastAPI:
    """Create the dashboard application.

    Passing an engine is useful for tests and embedding.  The default uses
    the project singleton from :mod:`vulnscan.storage.database`.
    """
    db_engine = engine or get_engine()
    migrate(db_engine)
    SessionFactory = sessionmaker(bind=db_engine, expire_on_commit=False)
    output = Path(export_dir)
    output.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="DevSecOps Agent", version=APP_VERSION)
    templates = Jinja2Templates(directory=str(_TEMPLATES))

    def session_dependency() -> Generator[Session, None, None]:
        with SessionFactory() as session:
            yield session

    SessionDep = Annotated[Session, Depends(session_dependency)]

    @app.middleware("http")
    async def csrf_protection(request: Request, call_next: Any) -> Response:
        """Double-submit CSRF protection for all state-changing requests."""
        token = request.cookies.get("vulnscan_csrf")
        if token is None:
            token = secrets.token_urlsafe(32)
        request.state.csrf_token = token

        if request.method not in _SAFE_METHODS:
            # Reading the form consumes the receive stream. Replay it so FastAPI's
            # Form(...) dependencies still see the same body downstream.
            body = await request.body()
            replayed = False

            async def receive() -> dict[str, Any]:
                nonlocal replayed
                if replayed:
                    return {"type": "http.disconnect"}
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = receive
            form = await request.form()
            supplied = request.headers.get("X-CSRF-Token") or form.get("_csrf")
            if not isinstance(supplied, str) or not hmac.compare_digest(supplied, token):
                return HTMLResponse("Invalid CSRF token", status_code=403)

        response = await call_next(request)
        response.set_cookie(
            "vulnscan_csrf",
            token,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
        )
        return cast(Response, response)

    def render(request: Request, name: str, **context: Any) -> HTMLResponse:
        response = templates.TemplateResponse(
            request=request,
            name=name,
            context={"csrf_token": request.state.csrf_token, **context},
        )
        # LEGACY Jinja UI marker (Phase 1): lets the SPA and tests tell the
        # legacy server-rendered pages apart from the new /app/* surface.
        response.headers["X-Pitwall-Legacy"] = "true"
        return response

    @app.middleware("http")
    async def contract_version(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["X-Contract-Version"] = "1"
        return cast(Response, response)

    @app.get("/", response_class=HTMLResponse)
    def target_registration(request: Request, session: SessionDep) -> HTMLResponse:
        runs = session.query(RunORM).order_by(RunORM.id.desc()).limit(10).all()
        return render(request, "targets.html", runs=runs)

    @app.post("/scans")
    def submit_scan(
        session: SessionDep,
        target_repository_url: str = Form(...),
        target_commit_sha: str = Form(...),
        repository_checkout_path: str = Form("."),
    ) -> RedirectResponse:
        service = ScanService(str(db_engine.url.database))
        result = service.run(
            repository_checkout_path,
            ScanConfig(output_dir=str(output)),
            repo=target_repository_url,
            expected_commit=target_commit_sha,
        )
        return RedirectResponse(f"/runs/{result['id']}", status_code=303)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_progress(run_id: int, request: Request, session: SessionDep) -> HTMLResponse:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        return render(
            request,
            "runs.html",
            run=run,
            target=run.target,
            stages=run.stages,
            findings=_findings_for_run(session, run_id),
        )

    @app.get("/runs/{run_id}/findings", response_class=HTMLResponse)
    def findings(run_id: int, request: Request, session: SessionDep) -> HTMLResponse:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        items = _findings_for_run(session, run_id)
        return render(
            request,
            "findings.html",
            run=run,
            findings=items,
            counts=ReportGenerator.counts(items),
        )

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    def evidence_detail(finding_id: str, request: Request, session: SessionDep) -> HTMLResponse:
        finding = _find_finding(session, finding_id)
        return render(request, "evidence.html", finding=finding)

    @app.get("/runs/{run_id}/findings/{finding_id}", response_class=HTMLResponse)
    def run_evidence(
        run_id: int, finding_id: str, request: Request, session: SessionDep
    ) -> HTMLResponse:
        for finding in _findings_for_run(session, run_id):
            if finding.finding_id == finding_id:
                return render(request, "evidence.html", finding=finding, run_id=run_id)
        raise HTTPException(404, "Finding not found in this run")

    @app.post("/findings/{finding_id}/status")
    def update_status(
        finding_id: str,
        session: SessionDep,
        status: str = Form(...),
        run_id: int | None = Form(None),
    ) -> RedirectResponse:
        try:
            new_status = FindingStatus(status)
        except ValueError as exc:
            raise HTTPException(422, f"Unknown status: {status}") from exc
        query = (
            session.query(FindingORM)
            .join(RunORM)
            .filter(FindingORM.finding_json.like(f'%"finding_id":"{finding_id}"%'))
        )
        if run_id is not None:
            query = query.filter(FindingORM.run_id == run_id)
        row = query.first()
        if row is None:
            raise HTTPException(404, "Finding not found")
        finding = Finding.model_validate_json(row.finding_json)
        finding.status = new_status
        row.finding_json = finding.model_dump_json()
        projection, searchable = project_finding(finding.model_dump(mode="json"))
        row.finding_id = finding.finding_id
        row.summary_json = json.dumps(projection)
        row.search_text = searchable
        saved_run = session.get(RunORM, row.run_id)
        if saved_run is not None:
            saved_run.findings_revision += 1
        session.commit()
        destination = (
            f"/runs/{run_id}/findings/{finding_id}"
            if run_id is not None
            else f"/findings/{finding_id}"
        )
        return RedirectResponse(destination, status_code=303)

    @app.get("/runs/{run_id}/export/{fmt}")
    def export(run_id: int, fmt: str, session: SessionDep) -> Response:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        try:
            export_format = ExportFormat(fmt)
        except ValueError as exc:
            raise HTTPException(422, f"Unsupported export: {fmt}") from exc
        snapshot = json.loads(run.result_json or "{}")
        report = ReportGenerator(
            run.public_id or str(run_id),
            _findings_for_run(session, run_id),
            coverage_summary=snapshot.get("coverage", {}),
            run_metadata={
                "commit": run.target.commit_sha,
                "status": run.status,
                "gate": snapshot.get("gate"),
                "errors": snapshot.get("errors", []),
            },
        )
        artifact = report.export(export_format, output, generated_by="dashboard")
        return Response(
            content=Path(artifact.artifact_ref.path).read_bytes(),
            media_type=_MIME[export_format],
            headers={
                "Content-Disposition": f'attachment; filename="{Path(artifact.artifact_ref.path).name}"'
            },
        )

    @app.get("/api/runs/{run_id}")
    def run_api(run_id: int, session: SessionDep) -> dict[str, Any]:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        items = _findings_for_run(session, run_id)
        snapshot = json.loads(run.result_json or "{}")
        return {
            "run_id": run.id,
            "status": run.status,
            "gate": snapshot.get("gate"),
            "counts": ReportGenerator.counts(items).model_dump(mode="json"),
            "stages": [
                {
                    "name": s.name,
                    "status": s.status,
                    "ordinal": s.ordinal,
                    "message": s.error_message or "",
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "completed_at": (s.completed_at.isoformat() if s.completed_at else None),
                }
                for s in sorted(run.stages, key=lambda s: s.ordinal)
            ],
            "reports": snapshot.get("reports", {}),
        }

    # ---- Phase 4 findings JSON surface --------------------------------------

    _SEVERITY_ORDER: tuple[str, ...] = (
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "undetermined",
    )

    def _severity_rank(value: str) -> int:
        try:
            return _SEVERITY_ORDER.index(value.lower())
        except ValueError:
            return len(_SEVERITY_ORDER)

    def _snapshot_of(run: RunORM) -> dict[str, Any]:
        try:
            data = json.loads(run.result_json or "{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _entries_by_finding(snapshot: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        raw = snapshot.get(key, [])
        if isinstance(raw, list):
            for entry in raw:
                if not isinstance(entry, dict):
                    continue
                fid = entry.get("finding_id")
                if not isinstance(fid, str):
                    nested = entry.get("finding")
                    if isinstance(nested, dict):
                        nested_id = nested.get("finding_id")
                        fid = nested_id if isinstance(nested_id, str) else None
                if isinstance(fid, str) and fid not in out:
                    out[fid] = entry
        return out

    def _observations_of(item: dict[str, Any]) -> list[dict[str, Any]]:
        obs = item.get("observations", [])
        if not isinstance(obs, list):
            return []
        return [o for o in obs if isinstance(o, dict)]

    def _scanners_of(item: dict[str, Any]) -> list[str]:
        tools: list[str] = []
        for obs in _observations_of(item):
            tool = str(obs.get("tool", ""))
            if tool and tool not in tools:
                tools.append(tool)
        return tools

    def _origin_of(item: dict[str, Any]) -> str:
        if "1104" in str(item.get("cwe_category", "")):
            return "dependency"
        for obs in _observations_of(item):
            if obs.get("dependency_identity"):
                return "dependency"
            if str(obs.get("tool", "")) == "owasp-dependency-check":
                return "dependency"
        return "source"

    def _primary_location(item: dict[str, Any]) -> tuple[str, int]:
        for obs in _observations_of(item):
            loc = obs.get("location")
            if isinstance(loc, dict):
                file_path = str(loc.get("file_path", ""))
                line = loc.get("line_start", 0)
                if file_path:
                    return file_path, int(line) if isinstance(line, int) else 0
        return "", 0

    def _list_item(item: dict[str, Any], assessment: dict[str, Any] | None) -> dict[str, Any]:
        observations = _observations_of(item)
        scanners = _scanners_of(item)
        first = observations[0] if observations else {}
        scanner_severity = str(first.get("severity", item.get("severity", "undetermined")))
        severity = str(item.get("severity", "undetermined"))
        proposed = str(assessment.get("proposed_severity", "")) if assessment else ""
        ai_severity = proposed or None
        file_path, line = _primary_location(item)
        return {
            "id": str(item.get("finding_id", "")),
            "title": str(item.get("title", "")),
            "severity": severity,
            "scanner_severity": scanner_severity,
            "ai_severity": ai_severity,
            "ai_changed": bool(ai_severity and ai_severity != scanner_severity),
            "cwe": str(item.get("cwe_category", "CWE-UNCLASSIFIED")),
            "status": str(item.get("status", "unprocessed")),
            "scanners": scanners,
            "file": file_path,
            "line": line,
            "origin": _origin_of(item),
        }

    def _csv_param(value: str | None) -> list[str]:
        if not value:
            return []
        return [part.strip().lower() for part in value.split(",") if part.strip()]

    def _finding_matches(
        entry: dict[str, Any],
        severities: list[str],
        cwes: list[str],
        scanners: list[str],
        verifications: list[str],
        ai_changed: bool | None,
        origin: str | None,
        terms: list[str],
    ) -> bool:
        if severities and str(entry["severity"]).lower() not in severities:
            return False
        if verifications and str(entry["status"]).lower() not in verifications:
            return False
        if scanners:
            entry_tools = [t.lower() for t in entry["scanners"]]
            if not any(any(want in tool for tool in entry_tools) for want in scanners):
                return False
        if cwes:
            cwe_text = str(entry["cwe"]).lower()
            cwe_digits = "".join(ch for ch in cwe_text if ch.isdigit())
            matched = False
            for want in cwes:
                if want in cwe_text:
                    matched = True
                    break
                want_digits = "".join(ch for ch in want if ch.isdigit())
                if want_digits and want_digits in cwe_digits:
                    matched = True
                    break
            if not matched:
                return False
        if ai_changed is not None and bool(entry["ai_changed"]) is not ai_changed:
            return False
        if origin and str(entry["origin"]).lower() != origin.lower():
            return False
        if terms:
            blob = " ".join(
                [
                    str(entry["id"]),
                    str(entry["title"]),
                    str(entry["file"]),
                    str(entry["cwe"]),
                    str(entry["status"]),
                    " ".join(entry["scanners"]),
                ]
            ).lower()
            if not all(term in blob for term in terms):
                return False
        return True

    @app.get("/api/scans/{run_id}/findings")
    def scan_findings(
        run_id: int,
        session: SessionDep,
        severity: str | None = Query(default=None),
        cwe: str | None = Query(default=None),
        scanner: str | None = Query(default=None),
        verification: str | None = Query(default=None),
        ai_changed: bool | None = Query(default=None),
        origin: str | None = Query(default=None),
        q: str | None = Query(default=None),
        sort: str = Query(default="severity"),
        order: str = Query(default="asc"),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        """Filtered, sorted, paginated finding list for one scan run."""
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        rows = (
            session.query(FindingORM).filter(FindingORM.run_id == run_id).order_by(FindingORM.id).all()
        )
        snapshot = _snapshot_of(run)
        assessments = _entries_by_finding(snapshot, "assessments")
        items: list[dict[str, Any]] = []
        for row in rows:
            try:
                raw = json.loads(row.finding_json or "{}")
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue
            fid = str(raw.get("finding_id", ""))
            if not fid:
                continue
            items.append(_list_item(raw, assessments.get(fid)))

        severities = _csv_param(severity)
        cwes = _csv_param(cwe)
        scanners = _csv_param(scanner)
        verifications = _csv_param(verification)
        terms = [t.lower() for t in (q or "").split() if t.strip()]
        if origin and origin.lower() not in ("source", "dependency"):
            raise HTTPException(422, "origin must be 'source' or 'dependency'")
        filtered = [
            entry
            for entry in items
            if _finding_matches(
                entry, severities, cwes, scanners, verifications, ai_changed, origin, terms
            )
        ]

        sort_key = sort.lower()
        descending = order.lower() == "desc"
        if sort_key == "title":
            filtered.sort(key=lambda e: str(e["title"]).lower(), reverse=descending)
        elif sort_key == "file":
            filtered.sort(
                key=lambda e: (str(e["file"]).lower(), int(e["line"])),
                reverse=descending,
            )
        elif sort_key == "status":
            filtered.sort(key=lambda e: str(e["status"]).lower(), reverse=descending)
        else:
            filtered.sort(
                key=lambda e: (_severity_rank(str(e["severity"])), str(e["title"]).lower()),
                reverse=descending,
            )

        total = len(filtered)
        start = (page - 1) * page_size
        return {
            "run_id": run_id,
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": filtered[start : start + page_size],
        }

    def _code_blocks(item: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        blocks: list[dict[str, Any]] = []
        taint: list[dict[str, Any]] = []
        for index, obs in enumerate(_observations_of(item)):
            loc = obs.get("location")
            file_path = ""
            line = 0
            if isinstance(loc, dict):
                file_path = str(loc.get("file_path", ""))
                raw_line = loc.get("line_start", 0)
                line = int(raw_line) if isinstance(raw_line, int) else 0
            snippet = str(loc.get("snippet", "")) if isinstance(loc, dict) else ""
            lines = [
                {"n": number, "text": text, "highlight": True}
                for number, text in enumerate(snippet.splitlines(), start=1)
            ]
            key = f"obs-{index}"
            blocks.append(
                {
                    "key": key,
                    "tool": str(obs.get("tool", "")),
                    "rule_id": str(obs.get("rule_id", "")),
                    "file": file_path,
                    "line": line,
                    "lines": lines,
                }
            )
            if file_path:
                taint.append(
                    {
                        "block": key,
                        "file": file_path,
                        "line": line,
                        "label": str(obs.get("rule_id", "")),
                    }
                )
        return blocks, taint

    @app.get("/api/findings/{finding_id}")
    def finding_detail(
        finding_id: str,
        session: SessionDep,
        run_id: int | None = Query(default=None),
    ) -> dict[str, Any]:
        """Full detail for one finding: evidence, AI assessment, verification."""
        query = session.query(FindingORM).order_by(FindingORM.id)
        if run_id is not None:
            run = session.get(RunORM, run_id)
            if run is None:
                raise HTTPException(404, "Run not found")
            query = query.filter(FindingORM.run_id == run_id)
        raw_item: dict[str, Any] | None = None
        owner_run_id: int | None = None
        for row in query.all():
            try:
                parsed = json.loads(row.finding_json or "{}")
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict) and str(parsed.get("finding_id", "")) == finding_id:
                raw_item = parsed
                owner_run_id = row.run_id
                break
        if raw_item is None or owner_run_id is None:
            raise HTTPException(404, "Finding not found")
        run = session.get(RunORM, owner_run_id)
        snapshot = _snapshot_of(run) if run is not None else {}
        assessment = _entries_by_finding(snapshot, "assessments").get(finding_id)
        decision = _entries_by_finding(snapshot, "validation_decisions").get(finding_id)

        ai: dict[str, Any] | None = None
        if assessment:
            cvss_raw = assessment.get("cvss")
            cvss: dict[str, Any] | None = None
            if isinstance(cvss_raw, dict):
                cvss = {
                    "vector": str(cvss_raw.get("vector", "")),
                    "base_score": cvss_raw.get("base_score"),
                    "qualitative": cvss_raw.get("qualitative"),
                    "notes": str(cvss_raw.get("notes", "")),
                }
            assumptions = assessment.get("assumptions", [])
            ai = {
                "proposed_severity": str(assessment.get("proposed_severity", "")) or None,
                "proposed_status": str(assessment.get("proposed_status", "")) or None,
                "cvss": cvss,
                "confidence": assessment.get("confidence"),
                "assumptions": [str(a) for a in assumptions] if isinstance(assumptions, list) else [],
                "rationale": str(assessment.get("rationale", "")),
            }

        verification_entry = _entries_by_finding(snapshot, "laya_verification").get(finding_id)
        checks: list[dict[str, Any]] = []
        for obs in _observations_of(raw_item):
            message = str(obs.get("message", ""))
            rule_id = str(obs.get("rule_id", ""))
            tool = str(obs.get("tool", ""))
            outcome = "not_verified"
            check = f"{tool} detection ({rule_id})" if rule_id else f"{tool} detection"
            if verification_entry is not None:
                outcome = str(
                    verification_entry.get(
                        "outcome", verification_entry.get("execution_status", "inconclusive")
                    )
                )
                check = str(
                    verification_entry.get("procedure_version", verification_entry.get("check", check))
                )
            checks.append({"claim": message, "check": check, "outcome": outcome})

        blocks, taint = _code_blocks(raw_item)
        summary = _list_item(raw_item, assessment)
        observations = [
            {
                "tool": str(obs.get("tool", "")),
                "rule_id": str(obs.get("rule_id", "")),
                "severity": str(obs.get("severity", "")),
                "message": str(obs.get("message", "")),
                "file": str((obs.get("location") or {}).get("file_path", ""))
                if isinstance(obs.get("location"), dict)
                else "",
                "line": (obs.get("location") or {}).get("line_start", 0)
                if isinstance(obs.get("location"), dict)
                else 0,
            }
            for obs in _observations_of(raw_item)
        ]
        return {
            **summary,
            "run_id": owner_run_id,
            "description": str(raw_item.get("description", "")),
            "additional_cwes": [str(c) for c in raw_item.get("additional_cwe_labels", [])]
            if isinstance(raw_item.get("additional_cwe_labels"), list)
            else [],
            "observations": observations,
            "code": {"blocks": blocks, "taint_path": taint},
            "ai": ai,
            "verification": {
                "checks": checks,
                "decision": {
                    "outcome": str(decision.get("outcome", "")),
                    "previous_status": str(decision.get("previous_status", "")),
                    "new_status": str(decision.get("new_status", "")),
                }
                if decision
                else None,
            },
            "raw": raw_item,
        }

    @app.get("/runs/{run_id}/report")
    def final_report(run_id: int, session: SessionDep) -> Response:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        snapshot = json.loads(run.result_json or "{}")
        path = (snapshot.get("reports") or {}).get("final-report", "")
        if not path or not Path(path).is_file():
            raise HTTPException(404, "Final report not generated for this run")
        return Response(
            content=Path(path).read_bytes(),
            media_type="text/markdown",
            headers={"Content-Disposition": 'attachment; filename="final-report.md"'},
        )

    def _find_finding(session: Session, finding_id: str) -> Finding:
        for row in session.query(FindingORM).order_by(FindingORM.id).all():
            finding = Finding.model_validate_json(row.finding_json)
            if finding.finding_id == finding_id:
                return finding
        raise HTTPException(404, "Finding not found")

    # ---- Phase 1 JSON surface (skeleton) -----------------------------------

    @app.get("/api/health")
    def api_health() -> dict[str, Any]:
        return {"status": "ok", "version": APP_VERSION, "contract": 1}

    @app.get("/api/csrf")
    def api_csrf(request: Request) -> dict[str, Any]:
        """Expose the double-submit CSRF token to the same-origin SPA.

        The ``vulnscan_csrf`` cookie is httponly so JS cannot read it; the
        SPA fetches it here before POST calls. Same-origin only (no CORS is
        configured) on a localhost-bound, single-user console.
        """
        return {"csrf_token": request.state.csrf_token}

    def _event_to_dict(row: ScanEventORM) -> dict[str, Any]:
        # Phase 5: server-side secret redaction on the Phase 1 surface too.
        return {
            "id": row.id,
            "seq": row.seq,
            "kind": row.kind,
            "stage": row.stage,
            "message": redact_secrets(row.message),
            "payload": redact_value(json.loads(row.payload_json or "{}")),
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    @app.get("/api/scans/{run_id}/events/history")
    def events_history(run_id: int, session: SessionDep) -> dict[str, Any]:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        rows = (
            session.query(ScanEventORM)
            .filter(ScanEventORM.run_id == run_id)
            .order_by(ScanEventORM.seq, ScanEventORM.id)
            .all()
        )
        items = [_event_to_dict(r) for r in rows]
        return {"run_id": run_id, "events": items, "next_cursor": len(items)}

    @app.get("/api/scans/{run_id}/events")
    async def events_stream(
        run_id: int, request: Request, session: SessionDep
    ) -> EventSourceResponse:
        """Phase 3 live SSE: hello + backlog + DB-polled tail + done hint.

        Replays stored ``scan_events`` rows newer than ``Last-Event-ID``
        (or ``?last_event_id=``), then — while the run is still
        queued/running — polls the table for new rows every 0.7s (up to
        ~60s per connection) so a long scan streams without websockets.
        Terminal runs close after a ``done`` event; live runs close after
        the poll budget with a ``live`` hint so the client reconnects with
        ``Last-Event-ID`` resume or falls back to ``?since=`` polling.
        """
        import asyncio

        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        raw_cursor = request.headers.get("last-event-id") or request.query_params.get(
            "last_event_id"
        )
        try:
            cursor = int(raw_cursor) if raw_cursor is not None else -1
        except ValueError:
            cursor = -1
        rows = (
            session.query(ScanEventORM)
            .filter(ScanEventORM.run_id == run_id, ScanEventORM.seq > cursor)
            .order_by(ScanEventORM.seq, ScanEventORM.id)
            .all()
        )
        payload = [_event_to_dict(r) for r in rows]
        status = run.status
        last_seq = max((item["seq"] for item in payload), default=cursor)
        terminal = status in {"completed", "failed", "cancelled"}

        async def generator() -> AsyncIterator[dict[str, Any]]:
            nonlocal last_seq
            yield {
                "event": "hello",
                "id": str(cursor),
                "retry": 1500,
                "data": json.dumps({"run_id": run_id, "status": status}),
            }
            for item in payload:
                yield {
                    "event": item["kind"],
                    "id": str(item["seq"]),
                    "data": json.dumps(item),
                }
            if terminal:
                yield {
                    "event": "done",
                    "id": str(last_seq),
                    "data": json.dumps(
                        {"type": "done", "run_id": run_id, "status": status}
                    ),
                }
                return
            # Live tail: poll a fresh session — the request-scoped session
            # would never see rows committed by the scanner process.
            for _ in range(85):
                if await request.is_disconnected():
                    break
                await asyncio.sleep(0.7)
                try:
                    with SessionFactory() as fresh:
                        fresh_run = fresh.get(RunORM, run_id)
                        fresh_status = fresh_run.status if fresh_run else "unknown"
                        fresh_rows = (
                            fresh.query(ScanEventORM)
                            .filter(
                                ScanEventORM.run_id == run_id,
                                ScanEventORM.seq > last_seq,
                            )
                            .order_by(ScanEventORM.seq, ScanEventORM.id)
                            .all()
                        )
                        fresh_items = [_event_to_dict(r) for r in fresh_rows]
                except Exception:  # noqa: BLE001, S112
                    continue
                for item in fresh_items:
                    last_seq = max(last_seq, int(item["seq"]))
                    yield {
                        "event": item["kind"],
                        "id": str(item["seq"]),
                        "data": json.dumps(item),
                    }
                if fresh_status in {"completed", "failed", "cancelled"}:
                    yield {
                        "event": "done",
                        "id": str(last_seq),
                        "data": json.dumps(
                            {
                                "type": "done",
                                "run_id": run_id,
                                "status": fresh_status,
                            }
                        ),
                    }
                    return
            yield {
                "event": "live",
                "data": json.dumps({"type": "live", "run_id": run_id, "status": status}),
            }

        return EventSourceResponse(generator())

    # ---- Phase 3 live scan detail + cancel/retry --------------------------

    @app.get("/api/scans/{run_id}")
    def scan_detail(run_id: int, session: SessionDep) -> dict[str, Any]:
        """Live scan snapshot: status, stages, AI evidence, usage, cursors."""
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        snapshot = _snapshot_of(run)
        rows = (
            session.query(FindingORM).filter(FindingORM.run_id == run_id).all()
        )
        counts = {"total": 0, "confirmed": 0, "rejected": 0, "unresolved": 0, "unprocessed": 0}
        severity: dict[str, int] = {}
        for row in rows:
            try:
                summary = json.loads(row.summary_json or "{}")
            except ValueError:
                summary = {}
            status_value = str(summary.get("status", "unprocessed"))
            counts["total"] += 1
            if status_value in counts:
                counts[status_value] += 1
            else:
                counts["unprocessed"] += 1
            sev = str(summary.get("severity", "info")).lower()
            severity[sev] = severity.get(sev, 0) + 1
        event_rows = (
            session.query(ScanEventORM)
            .filter(ScanEventORM.run_id == run_id)
            .order_by(ScanEventORM.seq, ScanEventORM.id)
            .all()
        )
        ai_usage = snapshot.get("ai_usage", {})
        if not isinstance(ai_usage, dict):
            ai_usage = {}
        assessments = snapshot.get("assessments", [])
        decisions = snapshot.get("validation_decisions", [])
        comparison = snapshot.get("comparison", {})
        comparison_counts: dict[str, int] = {}
        if isinstance(comparison, dict) and isinstance(comparison.get("counts"), dict):
            comparison_counts = {str(k): int(v) for k, v in comparison["counts"].items()}
        target = run.target
        return {
            "run_id": run.id,
            "repo": target.repository_url if target is not None else "",
            "commit": target.commit_sha if target is not None else "",
            "status": run.status,
            "gate": snapshot.get("gate", "unknown"),
            "counts": counts,
            "severity": severity,
            "stages": [
                {
                    "name": s.name,
                    "status": s.status,
                    "ordinal": s.ordinal,
                    "message": s.error_message or "",
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "completed_at": (s.completed_at.isoformat() if s.completed_at else None),
                }
                for s in sorted(run.stages, key=lambda s: s.ordinal)
            ],
            "ai": {
                "assessments": assessments if isinstance(assessments, list) else [],
                "decisions": decisions if isinstance(decisions, list) else [],
                "comparison_counts": comparison_counts,
                "usage": ai_usage,
            },
            "findings_revision": run.findings_revision,
            "event_cursor": max((r.seq for r in event_rows), default=-1),
            "event_count": len(event_rows),
            "created_at": run.created_at.isoformat() if run.created_at else None,
        }

    class _CancelIn(BaseModel):
        reason: str | None = None

    @app.post("/api/scans/{run_id}/cancel")
    def scan_cancel(run_id: int, session: SessionDep) -> dict[str, Any]:
        """Request cancellation: sets the flag a running scan polls.

        Queued runs flip to ``cancelled`` immediately; a running scan
        observes ``cancel_requested`` and stops at the next checkpoint.
        """
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        if run.status in {"completed", "failed", "cancelled"}:
            return {"run_id": run_id, "status": run.status, "cancel_requested": bool(run.cancel_requested)}
        run.cancel_requested = 1
        if run.status == "queued":
            run.status = "cancelled"
        session.commit()
        return {"run_id": run_id, "status": run.status, "cancel_requested": True}

    @app.post("/api/scans/{run_id}/retry", status_code=201)
    def scan_retry(run_id: int, session: SessionDep) -> dict[str, Any]:
        """Clone a terminal run into a fresh queued run (same target)."""
        from datetime import UTC as _UTC
        from datetime import datetime as _dt

        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        if run.status not in {"completed", "failed", "cancelled"}:
            raise HTTPException(409, "Only terminal runs can be retried")
        target = run.target
        if target is None:
            raise HTTPException(422, "Run has no target to retry")
        now = _dt.now(_UTC)
        clone = RunORM(
            target_id=target.id,
            status="queued",
            scan_spec_json=run.scan_spec_json,
            result_json=json.dumps({"gate": "unknown", "ai_usage": {}}),
            created_at=now,
            updated_at=now,
        )
        session.add(clone)
        session.flush()
        for ordinal, name in enumerate(
            [
                "intake",
                "model_hunt",
                "scanners",
                "laya_batch_routing",
                "laya_verification",
                "targeted_deep_analysis",
                "independent_validation",
                "final_report",
            ]
        ):
            session.add(StageORM(run_id=clone.id, ordinal=ordinal, name=name, status="pending"))
        session.commit()
        return {"run_id": clone.id, "status": "queued", "retried_from": run_id}

    # ---- Phase 5 Reports + Logs -------------------------------------------
    # Log lines are DERIVED (no dedicated event/log table beyond the Phase 1
    # ``scan_events`` table): stage rows + persisted ``scan_events`` + the
    # stored ``events_json`` list. There is no per-process stdout capture, so
    # granularity is coarse — every response says so honestly.

    _REPORT_SUFFIX: dict[str, str] = {
        "json": "json",
        "sarif": "sarif",
        "html": "html",
        "markdown": "md",
        "txt": "txt",
        "docx": "docx",
        "csv": "csv",
    }
    _REPORT_MIME: dict[str, str] = {
        "json": "application/json",
        "sarif": "application/sarif+json",
        "html": "text/html",
        "markdown": "text/markdown",
        "txt": "text/plain",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "csv": "text/csv",
    }
    _MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024
    _REPORT_ID_RE = re.compile(r"^run-(\d+)-([a-z0-9]+)\.([a-z0-9]+)$")
    _LOG_LEVELS = ("debug", "info", "warn", "error")
    _KIND_LEVEL: dict[str, str] = {
        "log": "info",
        "stage": "info",
        "ai_step": "debug",
        "ai_proposal": "debug",
        "verification_result": "info",
    }
    _GRANULARITY_NOTE = (
        "Coarse granularity: lines are derived from stage rows, persisted "
        "scan_events, and the stored events list. No per-process stdout "
        "capture exists."
    )

    class ReportRequest(BaseModel):
        format: str

    def _report_filename(run_id: int, fmt: str) -> str:
        return f"run-{run_id}-{fmt}.{_REPORT_SUFFIX[fmt]}"

    def _report_descriptor(
        run_id: int, fmt: str, total_findings: int
    ) -> dict[str, Any]:
        filename = _report_filename(run_id, fmt)
        path = output / filename
        generated = path.is_file()
        return {
            "report_id": filename,
            "run_id": run_id,
            "format": fmt,
            "filename": filename,
            "generated": generated,
            "size_bytes": path.stat().st_size if generated else None,
            "findings": total_findings,
            "download_url": f"/api/reports/{filename}/download" if generated else None,
        }

    def _report_generator(
        run_id: int, run: RunORM, findings: list[Finding]
    ) -> ReportGenerator:
        snapshot = json.loads(run.result_json or "{}")
        return ReportGenerator(
            run.public_id or str(run_id),
            findings,
            coverage_summary=snapshot.get("coverage", {}),
            run_metadata={
                "commit": run.target.commit_sha,
                "status": run.status,
                "gate": snapshot.get("gate"),
                "errors": snapshot.get("errors", []),
            },
        )

    @app.get("/api/scans/{run_id}/reports")
    def scan_reports(run_id: int, session: SessionDep) -> dict[str, Any]:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        findings = _findings_for_run(session, run_id)
        reports = [
            _report_descriptor(run_id, fmt, len(findings)) for fmt in _REPORT_SUFFIX
        ]
        snapshot = json.loads(run.result_json or "{}")
        final_path = (snapshot.get("reports") or {}).get("final-report", "")
        final: dict[str, Any] | None = None
        if final_path and Path(final_path).is_file():
            final_file = Path(final_path)
            final = {
                "report_id": "final-report.md",
                "run_id": run_id,
                "format": "markdown",
                "filename": "final-report.md",
                "generated": True,
                "size_bytes": final_file.stat().st_size,
                "findings": len(findings),
                "download_url": f"/runs/{run_id}/report",
            }
        return {
            "run_id": run_id,
            "reports": reports,
            "final_report": final,
            "csv_note": (
                "CSV is a flat finding-rows export "
                "(finding_id,title,severity,status,tools,file,line,cwe)."
            ),
        }

    @app.post("/api/scans/{run_id}/reports", status_code=201)
    def generate_report(
        run_id: int, request: ReportRequest, session: SessionDep
    ) -> dict[str, Any]:
        """Generate one report artifact synchronously.

        Generation is sub-second for typical runs; clients poll
        ``GET /api/scans/{id}/reports`` which flips ``generated`` to true —
        that poll is the "progress" contract for this endpoint.
        """
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        fmt = request.format.lower()
        if fmt not in _REPORT_SUFFIX:
            raise HTTPException(422, f"Unsupported format: {request.format}")
        findings = _findings_for_run(session, run_id)
        path = output / _report_filename(run_id, fmt)
        if fmt == "csv":
            path.write_text(findings_csv(findings), encoding="utf-8")
        else:
            generator = _report_generator(run_id, run, findings)
            artifact = generator.export(
                ExportFormat(fmt), output, generated_by="dashboard"
            )
            Path(artifact.artifact_ref.path).replace(path)
        descriptor = _report_descriptor(run_id, fmt, len(findings))
        descriptor["status"] = "ready"
        return descriptor

    @app.get("/api/reports/{report_id}/download")
    def download_report(report_id: str) -> Response:
        match = _REPORT_ID_RE.fullmatch(report_id)
        if match is None:
            raise HTTPException(400, "Invalid report id")
        fmt = match.group(2)
        if fmt not in _REPORT_SUFFIX or match.group(3) != _REPORT_SUFFIX[fmt]:
            raise HTTPException(400, "Invalid report id")
        try:
            resolved = (output / report_id).resolve()
        except OSError as exc:
            raise HTTPException(404, "Report not found") from exc
        if resolved.parent != output.resolve() or not resolved.is_file():
            raise HTTPException(404, "Report not found")
        data = resolved.read_bytes()
        if len(data) > _MAX_DOWNLOAD_BYTES:
            raise HTTPException(413, "Report exceeds the download size cap")
        return Response(
            content=data,
            media_type=_REPORT_MIME[fmt],
            headers={"Content-Disposition": f'attachment; filename="{report_id}"'},
        )

    def _finding_identity(finding: Finding) -> dict[str, Any]:
        data = finding.model_dump(mode="json")
        return {
            "finding_id": data.get("finding_id", ""),
            "title": data.get("title", ""),
            "severity": str(data.get("severity", "")),
            "status": str(data.get("status", "")),
        }

    @app.get("/api/compare")
    def compare_scans(
        request: Request,
        session: SessionDep,
        scan_ids: str = Query(default=""),
        export: str = Query(default="json"),
    ) -> Any:
        try:
            parsed = [int(part) for part in scan_ids.split(",") if part.strip()]
        except ValueError as exc:
            raise HTTPException(422, "scan_ids must be comma-separated integers") from exc
        ordered = list(dict.fromkeys(parsed))
        if len(ordered) < 2:
            raise HTTPException(422, "compare requires at least 2 scan ids")
        if len(ordered) > 6:
            raise HTTPException(422, "compare supports at most 6 scans")
        per_run: dict[int, list[Finding]] = {}
        gates: dict[int, Any] = {}
        statuses: dict[int, str] = {}
        for run_id in ordered:
            run = session.get(RunORM, run_id)
            if run is None:
                raise HTTPException(404, f"Run not found: {run_id}")
            per_run[run_id] = _findings_for_run(session, run_id)
            snapshot = json.loads(run.result_json or "{}")
            gates[run_id] = snapshot.get("gate")
            statuses[run_id] = run.status
        by_scanner: dict[str, dict[str, int]] = {}
        by_cwe: dict[str, dict[str, int]] = {}
        for run_id in ordered:
            for finding in per_run[run_id]:
                data = finding.model_dump(mode="json")
                observations = data.get("observations") or []
                seen_tools = {
                    str(obs.get("tool"))
                    for obs in observations
                    if isinstance(obs, dict) and obs.get("tool")
                }
                for tool in seen_tools or {"unknown"}:
                    by_scanner.setdefault(tool, {}).setdefault(str(run_id), 0)
                    by_scanner[tool][str(run_id)] += 1
                cwe = str(data.get("cwe_category", "") or "unclassified")
                by_cwe.setdefault(cwe, {}).setdefault(str(run_id), 0)
                by_cwe[cwe][str(run_id)] += 1
        baseline_id = ordered[0]
        baseline = {f.finding_id: f for f in per_run[baseline_id]}
        others: dict[str, Finding] = {}
        owners: dict[str, list[int]] = {}
        for run_id in ordered[1:]:
            for finding in per_run[run_id]:
                others.setdefault(finding.finding_id, finding)
                owners.setdefault(finding.finding_id, []).append(run_id)
        new = [
            {**_finding_identity(item), "seen_in": owners[fid]}
            for fid, item in others.items()
            if fid not in baseline
        ]
        fixed = [
            _finding_identity(item)
            for fid, item in baseline.items()
            if fid not in others
        ]
        changed = []
        for fid, item in baseline.items():
            if fid not in others:
                continue
            current = others[fid]
            if current.severity != item.severity or current.status != item.status:
                entry = _finding_identity(current)
                entry["baseline_severity"] = str(item.severity)
                entry["baseline_status"] = str(item.status)
                entry["seen_in"] = owners[fid]
                changed.append(entry)
        result: dict[str, Any] = {
            "baseline": baseline_id,
            "scans": [
                {
                    "run_id": run_id,
                    "status": statuses[run_id],
                    "gate": gates[run_id],
                    "total": len(per_run[run_id]),
                }
                for run_id in ordered
            ],
            "by_scanner": [
                {"tool": tool, "counts": counts}
                for tool, counts in sorted(by_scanner.items())
            ],
            "by_cwe": [
                {"cwe": cwe, "counts": counts} for cwe, counts in sorted(by_cwe.items())
            ],
            "new": new,
            "fixed": fixed,
            "changed": changed,
        }
        if export == "html":
            rows = "".join(
                f"<tr><td>{s['run_id']}</td><td>{s['status']}</td>"
                f"<td>{s['gate']}</td><td>{s['total']}</td></tr>"
                for s in result["scans"]
            )
            diff_items = "".join(
                f"<li>[{kind}] {entry.get('finding_id')}: "
                f"{redact_secrets(str(entry.get('title', '')))} "
                f"({entry.get('severity')}/{entry.get('status')})</li>"
                for kind, entries in (
                    ("new", new),
                    ("fixed", fixed),
                    ("changed", changed),
                )
                for entry in entries
            )
            return HTMLResponse(
                f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
                f"<title>Scan comparison {baseline_id} vs "
                f"{','.join(str(i) for i in ordered[1:])}</title></head>"
                f"<body><h1>Scan comparison</h1>"
                f"<table><tr><th>Run</th><th>Status</th><th>Gate</th>"
                f"<th>Findings</th></tr>{rows}</table>"
                f"<h2>Diff vs baseline #{baseline_id}</h2><ul>{diff_items}</ul>"
                f"</body></html>"
            )
        if export != "json":
            raise HTTPException(422, "export must be json or html")
        return result

    def _scan_log_lines(session: Session, run: RunORM) -> list[dict[str, Any]]:
        """Derive log lines from stages + scan_events + the stored event list."""
        lines: list[dict[str, Any]] = []
        for stage in sorted(run.stages, key=lambda item: item.ordinal):
            message = f"{stage.name} → {stage.status}"
            if stage.error_message:
                message += f": {stage.error_message}"
            lines.append(
                {
                    "source": stage.name or "stage",
                    "level": "error" if stage.status == "failed" else "info",
                    "kind": "stage",
                    "message": redact_secrets(message),
                    "ts": stage.completed_at.isoformat()
                    if stage.completed_at
                    else (
                        stage.started_at.isoformat() if stage.started_at else None
                    ),
                    "data": {
                        "ordinal": stage.ordinal,
                        "status": stage.status,
                    },
                    "finding_id": None,
                }
            )
        seen: set[tuple[str, str, str]] = {
            (str(item.get("kind")), str(item.get("source")), str(item.get("message")))
            for item in lines
        }
        event_rows = (
            session.query(ScanEventORM)
            .filter(ScanEventORM.run_id == run.id)
            .order_by(ScanEventORM.seq, ScanEventORM.id)
            .all()
        )
        for row in event_rows:
            payload = redact_value(json.loads(row.payload_json or "{}"))
            lines.append(
                {
                    "source": row.stage or "pipeline",
                    "level": _KIND_LEVEL.get(row.kind, "info"),
                    "kind": row.kind,
                    "message": redact_secrets(row.message),
                    "ts": row.created_at.isoformat() if row.created_at else None,
                    "data": payload,
                    "finding_id": payload.get("finding_id")
                    if isinstance(payload, dict)
                    else None,
                }
            )
            seen.add((row.kind, row.stage or "pipeline", row.message))
        try:
            stored = json.loads(run.events_json or "[]")
        except ValueError:
            stored = []
        if isinstance(stored, list):
            for item in stored:
                if isinstance(item, str):
                    entry = {"message": item, "source": "events", "level": "info"}
                elif isinstance(item, dict):
                    entry = item
                else:
                    continue
                key = (
                    str(entry.get("kind", "log")),
                    str(entry.get("source", "events")),
                    str(entry.get("message", "")),
                )
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    {
                        "source": str(entry.get("source", "events")),
                        "level": str(entry.get("level", "info")),
                        "kind": str(entry.get("kind", "log")),
                        "message": redact_secrets(str(entry.get("message", ""))),
                        "ts": entry.get("ts"),
                        "data": redact_value(entry.get("data", {})),
                        "finding_id": entry.get("finding_id"),
                    }
                )
        for seq, line in enumerate(lines):
            line["seq"] = seq
        return lines

    def _filtered_logs(
        session: Session,
        run: RunORM,
        level: str,
        source: str,
        query: str,
        since: int,
        limit: int,
    ) -> tuple[list[dict[str, Any]], int]:
        if level != "all" and level not in _LOG_LEVELS:
            raise HTTPException(422, f"Unknown level: {level}")
        lines = _scan_log_lines(session, run)
        lowered = query.lower()
        kept = [
            line
            for line in lines
            if line["seq"] > since
            and (level == "all" or line["level"] == level)
            and (source == "all" or line["source"] == source)
            and (not lowered or lowered in line["message"].lower())
        ]
        return kept[: max(1, min(limit, 2000))], (max((l["seq"] for l in lines), default=-1))

    @app.get("/api/logs")
    def logs_history(
        session: SessionDep,
        scan_id: int = Query(),
        level: str = Query(default="all"),
        source: str = Query(default="all"),
        q: str = Query(default=""),
        since: int = Query(default=-1),
        limit: int = Query(default=500),
    ) -> dict[str, Any]:
        run = session.get(RunORM, scan_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        lines, cursor = _filtered_logs(session, run, level, source, q, since, limit)
        return {
            "scan_id": scan_id,
            "lines": lines,
            "next_cursor": cursor,
            "redacted": True,
            "granularity": _GRANULARITY_NOTE,
        }

    @app.get("/api/logs/stream")
    async def logs_stream(
        scan_id: int,
        request: Request,
        session: SessionDep,
        level: str = Query(default="all"),
        source: str = Query(default="all"),
        q: str = Query(default=""),
    ) -> EventSourceResponse:
        """SSE replay of derived log lines, then a live hint (Phase 1 shape).

        Closes after the burst; the client falls back to polling
        ``GET /api/logs`` with ``?since=``.
        """
        run = session.get(RunORM, scan_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        lines, _cursor = _filtered_logs(session, run, level, source, q, -1, 2000)
        status = run.status

        async def generator() -> AsyncIterator[dict[str, Any]]:
            yield {
                "event": "hello",
                "id": "-1",
                "data": json.dumps({"scan_id": scan_id, "status": status}),
            }
            for line in lines:
                yield {
                    "event": "log",
                    "id": str(line["seq"]),
                    "data": json.dumps(line),
                }
            yield {
                "event": "live",
                "data": json.dumps(
                    {"type": "live", "scan_id": scan_id, "status": status}
                ),
            }

        return EventSourceResponse(generator())

    # ---- Phase 2 JSON surface (Home / New Scan / Keys) ----------------------
    from vulnscan.web.phase2_routes import register_phase2

    register_phase2(app, db_engine)

    # ---- Phase 1 SPA static mount (React build, optional) -------------------
    # web-ui/dist is copied to src/vulnscan/web/static/app at build/packaging
    # time; in a source checkout we also accept web-ui/dist in place so that
    # `npm run build && uvicorn` just works. Absence is fine (API + Jinja
    # still serve) — only mount when the directory exists.
    _dist = Path(__file__).with_name("static") / "app"
    _dev_dist = Path(__file__).resolve().parents[3] / "web-ui" / "dist"
    _spa_dir = _dist if _dist.is_dir() else (_dev_dist if _dev_dist.is_dir() else None)
    if _spa_dir is not None:
        _assets = _spa_dir / "assets"
        if _assets.is_dir():
            app.mount("/app/assets", StaticFiles(directory=_assets), name="spa-assets")

        @app.get("/app/{full_path:path}", include_in_schema=False)
        def spa_fallback(full_path: str) -> Response:
            candidate = _spa_dir / full_path
            if full_path and candidate.is_file():
                return Response(content=candidate.read_bytes())
            return Response(content=(_spa_dir / "index.html").read_bytes(), media_type="text/html")

    return app


app_factory = create_app
