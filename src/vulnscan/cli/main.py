"""Typer CLI entry point (devsecops-agent command)."""

from __future__ import annotations

import json

import typer
from sqlalchemy.exc import SQLAlchemyError

from ..storage.database import get_session, init_db
from ..storage.models import RunORM, TargetORM

app = typer.Typer(help="DevSecOps-Agent: automated vulnerability scanning.")


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context, version: bool = typer.Option(False, "--version", is_eager=True)
) -> None:
    import sys

    from ..version import APP_VERSION

    if version:
        typer.echo(APP_VERSION)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            launch_tui()
        else:
            typer.echo(ctx.get_help())


@app.command("db-init")
def db_init(db_path: str = typer.Option("vulnscan.db", help="SQLite file path.")) -> None:
    """Create all database tables."""
    init_db(db_path)
    typer.echo(f"Initialized database at {db_path}")


@app.command("target-add")
def target_add(
    url: str = typer.Argument(..., help="Git clone URL."),
    commit: str = typer.Argument(..., help="Pinned commit SHA (never 'HEAD')."),
    db_path: str = typer.Option("vulnscan.db", help="SQLite file path."),
) -> None:
    """Register a scan target."""
    init_db(db_path)
    with get_session(db_path) as session:
        target = TargetORM(repository_url=url, commit_sha=commit)
        session.add(target)
        session.flush()
        typer.echo(f"Added target id={target.id} ({url} @ {commit[:8]})")


@app.command("target-list")
def target_list(db_path: str = typer.Option("vulnscan.db", help="SQLite file path.")) -> None:
    """List registered targets."""
    init_db(db_path)
    with get_session(db_path) as session:
        for t in session.query(TargetORM).order_by(TargetORM.id).all():
            typer.echo(f"{t.id}	{t.commit_sha[:8]}	{t.repository_url}")


@app.command("scan-status")
def scan_status(
    run_id: str = typer.Argument(..., help="Public run ID or integer database ID."),
    db_path: str = typer.Option("vulnscan.db", "--db-path"),
) -> None:
    """Show the status of a retained scan."""
    from ..core.scan_service import ScanService

    try:
        detail = ScanService(db_path).detail(run_id)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"id={detail['id']} run={detail['run_id']} status={detail['status']}")


@app.command("scan-list")
def scan_list(db_path: str = typer.Option("vulnscan.db", help="SQLite file path.")) -> None:
    """List scan runs (newest first)."""
    init_db(db_path)
    with get_session(db_path) as session:
        for r in session.query(RunORM).order_by(RunORM.id.desc()).all():
            typer.echo(f"{r.id}	attempt={r.attempt}	{r.status}")


@app.command("scan-run")
def scan_run(
    checkout: str = typer.Option(".", "--checkout"),
    repo: str = typer.Option("local", "--repo"),
    commit: str = typer.Option("", "--commit"),
    profile: str | None = typer.Option(None, "--profile"),
    config_path: str | None = typer.Option(None, "--config"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    out: str | None = typer.Option(None, "--out"),
    db_path: str = typer.Option("vulnscan.db", "--db-path"),
    json_output: bool = typer.Option(False, "--json"),
    ci: bool | None = typer.Option(None, "--ci"),
    allow_dirty: bool | None = typer.Option(None, "--allow-dirty"),
    timeout: int | None = typer.Option(None, "--timeout"),
    laya: bool | None = typer.Option(None, "--laya"),
    laya_config_path: str | None = typer.Option(None, "--laya-config"),
    run_id: str | None = typer.Option(None, "--run-id"),
) -> None:
    """Scan, persist evidence and enforce policy (0 pass, 1 findings, 2 failure, 130 cancel)."""
    from pathlib import Path

    from ..core.config import resolve_config
    from ..core.scan_service import ScanService
    from ..core.security import sanitize

    try:
        config = resolve_config(
            profile,
            config_path,
            fail_on=fail_on,
            output_dir=out,
            ci=ci,
            allow_dirty=allow_dirty,
            timeout=timeout,
            laya=laya,
            laya_config_path=laya_config_path,
        )
        if not json_output:
            typer.echo(config.model_dump_json(indent=2))
        result = ScanService(db_path).run(
            checkout, config, repo=repo, expected_commit=commit, public_id=run_id
        )
    except (ValueError, OSError, SQLAlchemyError) as exc:
        result = {
            "status": "failed",
            "gate": "failed",
            "exit_code": 2,
            "errors": [sanitize(str(exc))],
            "run_id": None,
        }
        output = Path(out or "artifacts")
        try:
            output.mkdir(parents=True, exist_ok=True)
            (output / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        except OSError:
            result["errors"].append(
                "Summary could not be written; check output directory permissions"
            )
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(code=result["exit_code"])


@app.command("tui")
def tui(db_path: str = typer.Option("vulnscan.db", "--db-path")) -> None:
    """Open the full-screen terminal interface."""
    launch_tui(db_path)


def launch_tui(db_path: str = "vulnscan.db") -> None:
    import os
    import subprocess
    import sys

    from ..core.native import binary_path

    binary = binary_path()
    if binary and os.environ.get("DEVSECOPS_PYTHON_ONLY") != "1":
        env = {**os.environ, "DEVSECOPS_PYTHON": sys.executable}
        result = subprocess.run([binary, "tui", "--db-path", db_path], env=env, check=False)
        raise typer.Exit(result.returncode)
    from ..tui.app import ScanApp

    ScanApp(db_path).run()


@app.command("serve")
def serve(host: str = "127.0.0.1", port: int = 8000, db_path: str = "vulnscan.db") -> None:
    """Serve the existing local dashboard against the shared scan history."""
    import uvicorn

    from ..storage.database import get_engine
    from ..web.app import create_app

    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise typer.BadParameter("The dashboard must bind to localhost")
    uvicorn.run(create_app(engine=get_engine(db_path)), host=host, port=port)


@app.command("scan-export")
def scan_export(
    run_id: str, fmt: str = "json", out: str = "artifacts", db_path: str = "vulnscan.db"
) -> None:
    """Export retained evidence without rerunning scanners."""
    from ..contracts import ExportFormat
    from ..core.scan_service import ScanService

    typer.echo(ScanService(db_path).export(run_id, ExportFormat(fmt), out))


@app.command("scan-cancel")
def scan_cancel(run_id: str, db_path: str = "vulnscan.db") -> None:
    from ..core.scan_service import ScanService

    ScanService(db_path).cancel(run_id)


@app.command("scan-retry")
def scan_retry(run_id: str, db_path: str = "vulnscan.db") -> None:
    from ..core.scan_service import ScanService

    result = ScanService(db_path).retry(run_id)
    typer.echo(json.dumps(result, indent=2))
    raise typer.Exit(result["exit_code"])


@app.command("laya-config")
def laya_config(
    config_path: str = typer.Option("config/laya.json", help="Laya config JSON path."),
) -> None:
    """Show the resolved Laya decision-routing configuration.

    Advisory only: the resolved config can never enable status authority.
    """
    from ..decisions.config import load_config

    config = load_config(config_path)
    typer.echo(
        f"enabled={config.enabled} mode={config.mode} model={config.model_id} "
        f"revision={config.revision} device={config.device} "
        f"batch_size={config.batch_size} max_input_tokens={config.max_input_tokens} "
        f"affects_finding_status={config.affects_finding_status}"
    )


@app.command("laya-check")
def laya_check(
    load_model: bool = typer.Option(
        False, "--load-model", help="Also download and load the pinned model."
    ),
    model: str = typer.Option("convaiinnovations/laya", help="Model id or local path."),
) -> None:
    """Check whether the optional Laya dependency is usable locally."""
    try:
        import importlib

        laya = importlib.import_module("laya")
    except ImportError:
        typer.echo("laya=unavailable (optional dependency not installed)")
        return

    typer.echo(f"laya=available version={getattr(laya, 'VERSION', 'unknown')}")
    if not load_model:
        typer.echo("hint: re-run with --load-model to download weights (needs network)")
        return
    try:
        agent = laya.load(model)
    except Exception as exc:
        typer.echo(f"model_load=failed {type(exc).__name__}: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"model_load=ok device={getattr(agent, 'device', 'unknown')} "
        f"predict={callable(getattr(agent, 'predict', None))} "
        f"predict_batch={callable(getattr(agent, 'predict_batch', None))}"
    )


@app.command("laya-evaluate")
def laya_evaluate(
    scan: str = typer.Option(
        ..., "--scan", help="Scan JSON export with advisory_routing.payloads."
    ),
    truth: str = typer.Option(..., "--truth", help="Ground-truth JSON for evaluator grading."),
    out: str = typer.Option("", "--out", help="Optional path to write the experiment record."),
) -> None:
    """Grade one run's advisory routing against evaluator ground truth.

    The ground-truth file is the only answer key. Finding statuses are never
    consulted, so the advisory layer cannot grade itself.
    """
    from pathlib import Path as _Path

    from ..evaluation.laya_experiments import evaluate_from_files

    if not _Path(truth).is_file():
        typer.echo(f"ground truth not found: {truth}", err=True)
        raise typer.Exit(code=1)

    result = evaluate_from_files(_Path(scan), _Path(truth))
    rendered = json.dumps(result, indent=2, default=str)

    if out:
        _Path(out).parent.mkdir(parents=True, exist_ok=True)
        _Path(out).write_text(rendered, encoding="utf-8")
        typer.echo(f"experiment_record={out}")
    typer.echo(rendered)


@app.command("evidence-manifest")
def evidence_manifest(
    out: str = typer.Option("", "--out", help="Optional path to write the manifest."),
) -> None:
    """Build the handover evidence manifest with checksums and open blockers."""
    from pathlib import Path as _Path

    from ..evaluation.manifest import build_manifest

    manifest = build_manifest()
    rendered = json.dumps(manifest, indent=2, default=str)

    if out:
        _Path(out).parent.mkdir(parents=True, exist_ok=True)
        _Path(out).write_text(rendered, encoding="utf-8")
        typer.echo(f"manifest={out}")

    typer.echo(
        f"artifacts={len(manifest['artifacts'])} "
        f"missing={len(manifest['missing_artifacts'])} "
        f"blockers={len(manifest['blockers'])}"
    )
    for blocker in manifest["blockers"]:
        typer.echo(f"BLOCKER: {blocker}")
    typer.echo(rendered)


def main() -> None:
    """Console-script entry point (pyproject: vulnscan.cli.main:main)."""
    import os
    import subprocess
    import sys

    from ..core.native import binary_path

    binary = binary_path()
    if (
        binary
        and os.environ.get("DEVSECOPS_PYTHON_ONLY") != "1"
        and "--version" not in sys.argv[1:]
    ):
        result = subprocess.run(
            [binary, *sys.argv[1:]],
            env={**os.environ, "DEVSECOPS_PYTHON": sys.executable},
            check=False,
        )
        raise SystemExit(result.returncode)
    app()


if __name__ == "__main__":
    main()
