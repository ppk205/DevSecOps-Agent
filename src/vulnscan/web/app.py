"""FastAPI dashboard for scan intake, progress, findings, and evidence."""

import hmac
import json
import logging
import secrets
from collections.abc import Generator
from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from vulnscan.contracts.enums import ExportFormat, FindingStatus
from vulnscan.contracts.finding import Finding
from vulnscan.core.config import ScanConfig
from vulnscan.core.finding_view import project_finding
from vulnscan.core.scan_service import ScanService
from vulnscan.reporting.reporter import ReportGenerator
from vulnscan.storage.database import get_engine, migrate
from vulnscan.storage.models import FindingORM, RunORM
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
        return templates.TemplateResponse(
            request=request,
            name=name,
            context={"csrf_token": request.state.csrf_token, **context},
        )

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
                    "completed_at": (
                        s.completed_at.isoformat() if s.completed_at else None
                    ),
                }
                for s in sorted(run.stages, key=lambda s: s.ordinal)
            ],
            "reports": snapshot.get("reports", {}),
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

    return app


app_factory = create_app
