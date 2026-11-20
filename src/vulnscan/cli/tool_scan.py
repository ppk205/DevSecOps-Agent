"""CLI subcommands for invoking the 5 security scanner tools on demand.

Exposes the exact same :class:`ScannerToolService` facade used by the AI Agent
so developers, scripts, and MCP/tool wrappers can run targeted scans across all
7 language families and receive compact, token-optimized JSON output.
"""

from __future__ import annotations

import json
from typing import Any

import typer

from vulnscan.scanners.tool_service import ScannerToolService

tool_scan_app = typer.Typer(
    help="Run targeted scanner tools (Semgrep, CodeQL, OWASP/OSV, Gitleaks, SpotBugs/Trivy) and extract compact JSON."
)


def _emit(payload: dict[str, Any]) -> None:
    typer.echo(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


@tool_scan_app.command("capabilities")
def capabilities(
    root: str = typer.Option(".", "--root", help="Repository or snapshot directory."),
) -> None:
    """Inspect installed scanner binaries and detected language families."""
    svc = ScannerToolService(root)
    _emit(svc.capabilities())


@tool_scan_app.command("semgrep")
def scan_semgrep(
    root: str = typer.Option(".", "--root", help="Repository or snapshot directory."),
    target: str = typer.Option(".", "--target", help="Repo-relative file or directory to scan."),
    ruleset: str | None = typer.Option(None, "--ruleset", help="Ruleset pack (e.g. java, python, p/owasp-top-ten)."),
    cwe: str | None = typer.Option(None, "--cwe", help="Filter findings by CWE (e.g. CWE-89)."),
    language: str | None = typer.Option(None, "--language", help="Language family (java, javascript, python, php, go, cpp, csharp)."),
    max_items: int = typer.Option(15, "--max-items", help="Maximum extracted findings (1..50)."),
) -> None:
    """Run Semgrep AST/pattern analysis and extract compact findings."""
    svc = ScannerToolService(root)
    _emit(
        svc.run_semgrep(
            target_path=target,
            ruleset=ruleset,
            cwe=cwe,
            language=language,
            max_items=max_items,
        )
    )


@tool_scan_app.command("codeql")
def scan_codeql(
    root: str = typer.Option(".", "--root", help="Repository or snapshot directory."),
    target: str = typer.Option(".", "--target", help="Optional repo-relative path filter."),
    query_suite: str | None = typer.Option(None, "--query-suite", help="CodeQL query suite (e.g. java-security-extended.qls)."),
    cwe: str | None = typer.Option(None, "--cwe", help="Filter findings by CWE."),
    language: str | None = typer.Option(None, "--language", help="Language family (java, javascript, python, go, cpp, csharp)."),
    max_items: int = typer.Option(15, "--max-items", help="Maximum extracted findings (1..50)."),
) -> None:
    """Run CodeQL inter-procedural dataflow/taint analysis and extract compact findings."""
    svc = ScannerToolService(root)
    _emit(
        svc.run_codeql(
            target_path=target,
            query_suite=query_suite,
            cwe=cwe,
            language=language,
            max_items=max_items,
        )
    )


@tool_scan_app.command("owasp")
def scan_owasp(
    root: str = typer.Option(".", "--root", help="Repository or snapshot directory."),
    manifest: str | None = typer.Option(None, "--manifest", help="Optional repo-relative manifest file path."),
    min_cvss: float | None = typer.Option(None, "--min-cvss", help="Minimum CVSS base score filter."),
    max_items: int = typer.Option(15, "--max-items", help="Maximum extracted CVEs (1..50)."),
) -> None:
    """Run OWASP Dependency-Check (with OSV.dev fallback) across 7 language manifests."""
    svc = ScannerToolService(root)
    _emit(
        svc.run_owasp(
            manifest_path=manifest,
            min_cvss=min_cvss,
            max_items=max_items,
        )
    )


@tool_scan_app.command("secrets")
def scan_secrets(
    root: str = typer.Option(".", "--root", help="Repository or snapshot directory."),
    target: str = typer.Option(".", "--target", help="Repo-relative path to scan."),
    git_history: bool = typer.Option(False, "--git-history", help="Also scan git commit history."),
    max_items: int = typer.Option(15, "--max-items", help="Maximum extracted findings (1..50)."),
) -> None:
    """Run Gitleaks secret detection across source files and optional git history."""
    svc = ScannerToolService(root)
    _emit(
        svc.run_secret_scan(
            target_path=target,
            scan_git_history=git_history,
            max_items=max_items,
        )
    )


@tool_scan_app.command("config")
def scan_config(
    root: str = typer.Option(".", "--root", help="Repository or snapshot directory."),
    target: str = typer.Option(".", "--target", help="Repo-relative path to audit."),
    check_type: str = typer.Option("auto", "--check-type", help="Audit mode: auto, bytecode (SpotBugs), or iac_config (Trivy)."),
    max_items: int = typer.Option(15, "--max-items", help="Maximum extracted findings (1..50)."),
) -> None:
    """Run Java bytecode (SpotBugs) or IaC/container config (Trivy) security audit."""
    svc = ScannerToolService(root)
    _emit(
        svc.run_config_audit(
            target_path=target,
            check_type=check_type,
            max_items=max_items,
        )
    )


@tool_scan_app.command("explain")
def explain_rule(
    rule_id: str = typer.Argument(..., help="Scanner rule ID to explain."),
    tool: str | None = typer.Option(None, "--tool", help="Optional tool name hint."),
) -> None:
    """Explain a scanner rule ID with CWE metadata and remediation guidance."""
    svc = ScannerToolService(".")
    _emit(svc.explain_rule(rule_id=rule_id, tool=tool))


__all__ = ["tool_scan_app"]
