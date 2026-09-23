"""FastAPI dashboard for scan intake, progress, findings, and evidence."""

import hmac
import logging
import secrets
from collections.abc import Generator
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from vulnscan.contracts import ScanSpecification
from vulnscan.contracts.enums import ExportFormat, FindingStatus
from vulnscan.contracts.finding import Finding
from vulnscan.core.job_manager import JobManager
from vulnscan.reporting.reporter import ReportGenerator
from vulnscan.storage.database import get_engine
from vulnscan.storage.models import Base, FindingORM, RunORM

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
        session.query(FindingORM)
        .filter(FindingORM.run_id == run_pk)
        .order_by(FindingORM.id)
        .all()
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
    Base.metadata.create_all(db_engine)
    Session = sessionmaker(bind=db_engine, expire_on_commit=False)
    output = Path(export_dir)
    output.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="DevSecOps Agent", version="0.1.0")
    templates = Jinja2Templates(directory=str(_TEMPLATES))

    def session_dependency() -> Generator[Session, None, None]:
        with Session() as session:
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

            request._receive = receive  # type: ignore[attr-defined]
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
        return response

    def render(request: Request, name: str, **context: Any) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name=name,
            context={"csrf_token": request.state.csrf_token, **context},
        )

    @app.get("/", response_class=HTMLResponse)
    def target_registration(request: Request, session: SessionDep):
        runs = session.query(RunORM).order_by(RunORM.id.desc()).limit(10).all()
        return render(request, "targets.html", runs=runs)

    @app.post("/scans")
    def submit_scan(
        session: SessionDep,
        target_repository_url: str = Form(...),
        target_commit_sha: str = Form(...),
        repository_checkout_path: str = Form("."),
    ) -> RedirectResponse:
        spec = ScanSpecification(
            target_repository_url=target_repository_url,
            target_commit_sha=target_commit_sha,
            repository_checkout_path=repository_checkout_path,
        )
        run_id = JobManager(session).submit_scan(spec)
        session.commit()
        return RedirectResponse(f"/runs/{run_id}", status_code=303)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_progress(
        run_id: int, request: Request, session: SessionDep
    ):
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
    def findings(
        run_id: int, request: Request, session: SessionDep
    ):
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
    def evidence_detail(
        finding_id: str, request: Request, session: SessionDep
    ):
        finding = _find_finding(session, finding_id)
        return render(request, "evidence.html", finding=finding)

    @app.post("/findings/{finding_id}/status")
    def update_status(
        finding_id: str,
        session: SessionDep,
        status: str = Form(...),
    ) -> RedirectResponse:
        try:
            new_status = FindingStatus(status)
        except ValueError as exc:
            raise HTTPException(422, f"Unknown status: {status}") from exc
        row = (
            session.query(FindingORM)
            .join(RunORM)
            .filter(FindingORM.finding_json.like(f'%"finding_id":"{finding_id}"%'))
            .first()
        )
        if row is None:
            raise HTTPException(404, "Finding not found")
        finding = Finding.model_validate_json(row.finding_json)
        finding.status = new_status
        row.finding_json = finding.model_dump_json()
        session.commit()
        return RedirectResponse(f"/findings/{finding_id}", status_code=303)

    @app.get("/runs/{run_id}/export/{fmt}")
    def export(
        run_id: int, fmt: str, session: SessionDep
    ) -> Response:
        run = session.get(RunORM, run_id)
        if run is None:
            raise HTTPException(404, "Run not found")
        try:
            export_format = ExportFormat(fmt)
        except ValueError as exc:
            raise HTTPException(422, f"Unsupported export: {fmt}") from exc
        report = ReportGenerator(str(run_id), _findings_for_run(session, run_id))
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
        return {
            "run_id": run.id,
            "status": run.status,
            "counts": ReportGenerator.counts(items).model_dump(mode="json"),
        }

    def _find_finding(session: Session, finding_id: str) -> Finding:
        for row in session.query(FindingORM).order_by(FindingORM.id).all():
            finding = Finding.model_validate_json(row.finding_json)
            if finding.finding_id == finding_id:
                return finding
        raise HTTPException(404, "Finding not found")

    return app


app_factory = create_app
