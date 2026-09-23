"""Typer CLI entry point (devsecops-agent command)."""

from __future__ import annotations

import typer

from ..storage.database import get_session, init_db
from ..storage.models import RunORM, TargetORM

app = typer.Typer(help="DevSecOps-Agent: automated vulnerability scanning.")


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
    run_id: int = typer.Argument(..., help="Run id."),
    db_path: str = typer.Option("vulnscan.db", help="SQLite file path."),
) -> None:
    """Show the status of a scan run."""
    init_db(db_path)
    with get_session(db_path) as session:
        run = session.get(RunORM, run_id)
        if run is None:
            typer.echo(f"No run with id {run_id}", err=True)
            raise typer.Exit(code=1)
        typer.echo(
            f"run={run.id} attempt={run.attempt} status={run.status} "
            f"target={run.target.commit_sha[:8]}"
        )


@app.command("scan-list")
def scan_list(db_path: str = typer.Option("vulnscan.db", help="SQLite file path.")) -> None:
    """List scan runs (newest first)."""
    init_db(db_path)
    with get_session(db_path) as session:
        for r in session.query(RunORM).order_by(RunORM.id.desc()).all():
            typer.echo(f"{r.id}	attempt={r.attempt}	{r.status}")


def main() -> None:
    """Console-script entry point (pyproject: vulnscan.cli.main:main)."""
    app()


if __name__ == "__main__":
    main()
