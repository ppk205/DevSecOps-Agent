"""Phase 2 JSON surface (PIT WALL Home / New Scan / Keys).

Thin over existing services: tools via adapter ``which`` probes, keys via
project-local ``.env`` + ``.providers/*.json``, usage vs the USD 50 ceiling.
Mounted from :func:`vulnscan.web.app.create_app` via :func:`register_phase2`.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from vulnscan.infra.envfile import EnvFile
from vulnscan.providers.profile_store import (
    delete_profile,
    list_profiles,
    load_profile,
    save_profile,
)
from vulnscan.web.phase2 import (
    BUDGET_TOTAL_USD,
    aggregate_usage,
    key_status,
    key_value,
    load_general_settings,
    probe_tools,
    save_general_settings,
    unset_key,
)

router = APIRouter()


def _session(request: Request) -> Session:
    from sqlalchemy.orm import sessionmaker

    from vulnscan.storage.database import get_engine, migrate

    engine = getattr(request.app.state, "db_engine", None) or get_engine()
    migrate(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    return factory()


class GeneralSettingsIn(BaseModel):
    timezone: str | None = None
    timeout: int | None = None
    max_files: int | None = None
    output_dir: str | None = None
    fail_on: str | None = None
    profile: str | None = None


class KeyPutIn(BaseModel):
    api_key: str
    base_url: str | None = None
    label: str | None = None
    api_key_env: str | None = None
    models: list[str] | None = None
    default_model: str | None = None


class ScanCreateIn(BaseModel):
    repository_url: str
    commit_sha: str | None = None
    checkout_path: str | None = None
    profile: str | None = "fast"
    tools: list[str] | None = None
    ai_review: bool = False
    provider_profile: str | None = None
    provider_model: str | None = None
    max_ai_findings: int | None = 10
    timeout: int | None = None
    max_files: int | None = None
    mode: str | None = "deterministic"


def _scan_to_summary(
    run: Any,
    repo: str,
    commit: str,
    counts: dict[str, int],
    severity: dict[str, int] | None = None,
    top_cwe: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    from vulnscan.storage.models import RunORM  # noqa: F401  (typing aid)

    snapshot: dict[str, Any] = {}
    try:
        snapshot = json.loads(run.result_json or "{}")
    except ValueError:
        snapshot = {}
    return {
        "run_id": run.id,
        "repo": repo,
        "commit": commit,
        "status": run.status,
        "gate": snapshot.get("gate", "unknown"),
        "counts": counts,
        "severity": severity or {},
        "top_cwe": top_cwe or [],
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


def _tallies_for_run(
    session: Session, run_id: int
) -> tuple[dict[str, int], dict[str, int], list[dict[str, Any]]]:
    from vulnscan.storage.models import FindingORM

    counts = {"total": 0, "confirmed": 0, "rejected": 0, "unresolved": 0, "unprocessed": 0}
    severity: dict[str, int] = {}
    cwe: dict[str, int] = {}
    rows = session.query(FindingORM).filter(FindingORM.run_id == run_id).all()
    for row in rows:
        try:
            summary = json.loads(row.summary_json or "{}")
        except ValueError:
            summary = {}
        status = str(summary.get("status", "unprocessed"))
        counts["total"] += 1
        if status in counts:
            counts[status] += 1
        else:
            counts["unprocessed"] += 1
        sev = str(summary.get("severity", "info")).lower()
        severity[sev] = severity.get(sev, 0) + 1
        cwe_name = str(summary.get("cwe_category", "") or "")
        if cwe_name:
            cwe[cwe_name] = cwe.get(cwe_name, 0) + 1
    top = [
        {"cwe": name, "count": n}
        for name, n in sorted(cwe.items(), key=lambda kv: kv[1], reverse=True)[:8]
    ]
    return counts, severity, top


@router.get("/api/tools")
def api_tools(verify: bool = Query(default=False)) -> dict[str, Any]:
    return {"tools": probe_tools(with_versions=verify)}


@router.get("/api/settings")
def api_settings_get() -> dict[str, Any]:
    return {"general": load_general_settings()}


@router.put("/api/settings")
def api_settings_put(body: GeneralSettingsIn) -> dict[str, Any]:
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        saved = save_general_settings(patch)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"general": saved}


@router.get("/api/settings/keys")
def api_keys_list() -> dict[str, Any]:
    from vulnscan.contracts.provider import ProviderProfile  # noqa: F401

    profiles = list_profiles()
    env = EnvFile()
    items: list[dict[str, Any]] = []
    for profile in profiles:
        status = key_status(profile.api_key_env, env)
        items.append(
            {
                "profile": profile.id,
                "label": profile.label,
                "base_url": profile.base_url,
                "api_key_env": profile.api_key_env,
                "models": profile.models,
                "default_model": profile.default_model,
                "configured": status["configured"],
                "masked": status["masked"],
            }
        )
    return {"keys": items}


@router.put("/api/settings/keys/{profile}")
def api_key_put(profile: str, body: KeyPutIn) -> dict[str, Any]:
    from vulnscan.contracts.enums import ProviderProtocol
    from vulnscan.contracts.provider import ProviderProfile

    slug = profile.strip().lower()
    if not slug.replace("-", "").replace("_", "").isalnum() or len(slug) < 3 or len(slug) > 64:
        raise HTTPException(422, "Invalid profile id")
    raw = (body.api_key or "").strip()
    if not raw:
        raise HTTPException(422, "Refusing to store an empty secret")
    try:
        existing = load_profile(slug)
    except FileNotFoundError:
        existing = None
    api_key_env = body.api_key_env or (
        existing.api_key_env if existing else f"{slug.upper().replace('-', '_')}_API_KEY"
    )
    api_key_env = api_key_env.strip().upper().replace("-", "_")
    base_url = body.base_url or (existing.base_url if existing else "https://api.openai.com/v1")
    label = body.label or (existing.label if existing else slug)
    models = body.models if body.models is not None else (existing.models if existing else [])
    default_model = (
        body.default_model
        if body.default_model is not None
        else (existing.default_model if existing else None)
    )
    # Preserve custom headers (e.g. opencode session routing) — a key-only
    # update must not wipe profile transport settings.
    headers = dict(existing.headers) if existing and existing.headers else {}
    metadata = dict(existing.metadata) if existing and existing.metadata else {}
    # Key stays in process env / project .env only — never on the profile JSON.
    EnvFile().set(api_key_env, raw)
    saved = ProviderProfile(
        id=slug,
        label=label,
        protocol=ProviderProtocol.OPENAI_COMPATIBLE,
        base_url=base_url,
        api_key_env=api_key_env,
        models=models,
        default_model=default_model,
        headers=headers,
        metadata=metadata,
    )
    save_profile(saved)
    status = key_status(api_key_env)
    return {
        "profile": slug,
        "label": label,
        "base_url": base_url,
        "api_key_env": api_key_env,
        "configured": status["configured"],
        "masked": status["masked"],
    }


@router.delete("/api/settings/keys/{profile}")
def api_key_delete(profile: str) -> dict[str, Any]:
    slug = profile.strip().lower()
    try:
        existing = load_profile(slug)
    except FileNotFoundError:
        raise HTTPException(404, "Profile not found") from None
    delete_profile(slug)
    unset_key(existing.api_key_env)
    return {"deleted": True, "profile": slug}


@router.post("/api/settings/keys/{profile}/test")
def api_key_test(profile: str) -> dict[str, Any]:
    slug = profile.strip().lower()
    try:
        existing = load_profile(slug)
    except FileNotFoundError:
        raise HTTPException(404, "Profile not found") from None
    secret = key_value(existing.api_key_env)
    if not secret:
        raise HTTPException(422, f"Key {existing.api_key_env} is not configured")
    model = existing.default_model or (existing.models[0] if existing.models else "gpt-4o-mini")
    url = existing.base_url.rstrip("/") + "/chat/completions"
    started = time.monotonic()
    try:
        with httpx.Client(timeout=10.0) as client:
            real = client.post(
                url,
                headers={"Authorization": f"Bearer {secret}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 8,
                    "temperature": 0.0,
                },
            )
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "profile": slug,
            "model": model,
            "error": f"{type(exc).__name__}: {exc}",
        }
    latency_ms = int((time.monotonic() - started) * 1000)
    if real.status_code < 400:
        return {"ok": True, "profile": slug, "model": model, "latency_ms": latency_ms}
    detail = real.text[:300]
    return {
        "ok": False,
        "profile": slug,
        "model": model,
        "error": f"HTTP {real.status_code}: {detail}",
    }


@router.get("/api/usage")
def api_usage(request: Request) -> dict[str, Any]:
    from vulnscan.storage.models import RunORM

    session = _session(request)
    try:
        snapshots: list[dict[str, Any]] = []
        for run in session.query(RunORM).all():
            try:
                snapshots.append(json.loads(run.result_json or "{}"))
            except ValueError:
                continue
        summary = aggregate_usage(snapshots)
        return {**summary, "run_count": len(snapshots)}
    finally:
        session.close()


@router.get("/api/scans")
def api_scans(
    request: Request,
    status: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    from vulnscan.storage.models import RunORM

    session = _session(request)
    try:
        query = session.query(RunORM).order_by(RunORM.id.desc())
        if status:
            query = query.filter(RunORM.status == status)
        runs = query.limit(limit).all()
        items: list[dict[str, Any]] = []
        for run in runs:
            target = run.target
            repo = target.repository_url if target is not None else ""
            commit = target.commit_sha if target is not None else ""
            counts, severity, top_cwe = _tallies_for_run(session, run.id)
            items.append(_scan_to_summary(run, repo, commit, counts, severity, top_cwe))
        return {"scans": items, "total": len(items)}
    finally:
        session.close()


@router.post("/api/scans")
def api_scans_create(
    request: Request, body: ScanCreateIn, background: BackgroundTasks
) -> dict[str, Any]:
    import uuid as _uuid

    from vulnscan.storage.models import RunORM, StageORM, TargetORM

    repo = (body.repository_url or "").strip()
    if not repo:
        raise HTTPException(422, "repository_url is required")
    profile = (body.profile or "fast").strip()
    if profile not in {"fast", "full"}:
        raise HTTPException(422, "profile must be fast|full")
    commit = (body.commit_sha or "").strip() or ("0" * 40)
    checkout = (body.checkout_path or "").strip() or repo
    public_id = "web-" + _uuid.uuid4().hex[:12]
    params = {
        "checkout": checkout,
        "repo": repo,
        "commit": body.commit_sha or "",
        "profile": profile,
        "tools": list(body.tools or []),
        "ai_review": body.ai_review,
        "provider_profile": body.provider_profile,
        "provider_model": body.provider_model,
        "max_ai_findings": body.max_ai_findings or 10,
        "timeout": body.timeout,
        "max_files": body.max_files,
        "mode": (body.mode or "deterministic").strip(),
    }
    session = _session(request)
    try:
        target = (
            session.query(TargetORM)
            .filter(TargetORM.repository_url == repo)
            .order_by(TargetORM.id.desc())
            .first()
        )
        if target is None:
            target = TargetORM(repository_url=repo, commit_sha=commit)
            session.add(target)
            session.flush()
        run = RunORM(
            target_id=target.id,
            public_id=public_id,
            status="queued",
            scan_spec_json=json.dumps({"configuration": params}),
            result_json=json.dumps({"gate": "unknown", "ai_usage": {}}),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        session.add(run)
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
            session.add(StageORM(run_id=run.id, ordinal=ordinal, name=name, status="pending"))
        session.commit()
        run_id = run.id
    finally:
        session.close()
    engine = getattr(request.app.state, "db_engine", None)
    db_path = str(engine.url.database) if engine is not None else "vulnscan.db"
    output_dir = getattr(request.app.state, "export_dir", None) or "artifacts/reports"
    background.add_task(_execute_web_scan, db_path, output_dir, public_id, params)
    return {"run_id": run_id, "status": "queued", "profile": profile}


def _execute_web_scan(
    db_path: str, output_dir: str, public_id: str, params: dict[str, Any]
) -> None:
    """Run the real pipeline in the background, adopting the queued row.

    Failures are recorded on the run (never silent): the live page polls
    the same run id and shows the error instead of spinning forever.
    """
    from vulnscan.core.config import resolve_config
    from vulnscan.core.scan_service import ScanService
    from vulnscan.core.source import resolve_source
    from vulnscan.storage.database import get_session
    from vulnscan.storage.models import RunORM

    def _fail(message: str) -> None:
        try:
            with get_session(db_path) as session:
                row = session.query(RunORM).filter_by(public_id=public_id).first()
                if row is None:
                    return
                row.status = "failed"
                try:
                    snapshot = json.loads(row.result_json or "{}")
                except ValueError:
                    snapshot = {}
                errors = list(snapshot.get("errors", []))
                errors.append(message[:500])
                snapshot["errors"] = errors
                row.result_json = json.dumps(snapshot)
        except Exception:  # noqa: BLE001, S110 - failure recorder must never crash the worker
            pass

    try:
        mode = (params.get("mode") or "hunt").strip()
        if mode not in ("deterministic", "hunt"):
            raise ValueError(f"Unknown scan mode: {mode}")
        # Hunt without an explicit provider auto-resolves the default keyed
        # profile inside the service; without any key it skips with a reason.
        config = resolve_config(
            params.get("profile") or "fast",
            None,
            fail_on="high",
            output_dir=output_dir,
            timeout=params.get("timeout"),
            max_files=params.get("max_files"),
            ai_review=params.get("ai_review") or mode == "hunt",
            provider_profile=params.get("provider_profile"),
            provider_model=params.get("provider_model"),
            ai_report=bool(params.get("provider_profile")) or mode == "hunt",
            max_ai_findings=params.get("max_ai_findings") or 10,
            tools=params.get("tools") or None,
            mode=mode,
        )
    except Exception as exc:  # noqa: BLE001 - record config errors on the run, never raise from worker
        _fail(f"Invalid scan configuration: {exc}")
        return
    try:
        source = resolve_source(params["checkout"], "harness", commit=params.get("commit") or "")
    except Exception as exc:  # noqa: BLE001 - record checkout errors on the run, never raise from worker
        _fail(f"Cannot resolve checkout: {type(exc).__name__}: {exc}")
        return
    try:
        ScanService(db_path).run(
            source.checkout,
            config,
            repo=params["repo"],
            expected_commit=source.commit,
            public_id=public_id,
        )
    except Exception as exc:  # noqa: BLE001 - record pipeline errors on the run, never raise from worker
        _fail(f"{type(exc).__name__}: {exc}")


def register_phase2(app: Any, db_engine: Any) -> None:
    """Mount the Phase 2 router and expose the engine for request sessions."""
    app.state.db_engine = db_engine
    app.include_router(router)
    _ = (BUDGET_TOTAL_USD, EnvFile, os.environ, Path, time)
