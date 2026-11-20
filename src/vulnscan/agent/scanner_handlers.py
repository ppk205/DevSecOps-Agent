"""Agent tool handler factory for the 5 security scanners + query/explain tools.

Wraps :class:`vulnscan.scanners.tool_service.ScannerToolService` into the
``Callable[[dict[str, Any]], dict[str, Any]]`` handler signature expected by
:class:`vulnscan.agent.loop.AgentLoop` and :func:`vulnscan.ai.hunt.hunt_vulns`.

Every handler enforces strict argument coercion and never raises across the tool
boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from vulnscan.contracts import Finding
from vulnscan.scanners.tool_service import ScannerToolService

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


def _coerce_int(value: Any, default: int, *, minimum: int = 1, maximum: int = 50) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _coerce_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def build_scanner_tool_handlers(
    snapshot_root: str | Path,
    findings: Sequence[Finding] = (),
    *,
    service: ScannerToolService | None = None,
) -> dict[str, ToolHandler]:
    """Create bounded, snapshot-jailed handlers for all scanner agent tools."""
    svc = service or ScannerToolService(snapshot_root, findings=findings)

    def run_semgrep_scan(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return svc.run_semgrep(
                target_path=_coerce_str(args.get("target_path")) or ".",
                ruleset=_coerce_str(args.get("ruleset")),
                cwe=_coerce_str(args.get("cwe")),
                language=_coerce_str(args.get("language")),
                max_items=_coerce_int(args.get("max_items"), 15),
            )
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"tool": "semgrep", "status": "error", "error": str(exc)[:500]}

    def run_codeql_scan(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return svc.run_codeql(
                target_path=_coerce_str(args.get("target_path")) or ".",
                query_suite=_coerce_str(args.get("query_suite")),
                cwe=_coerce_str(args.get("cwe")),
                language=_coerce_str(args.get("language")),
                max_items=_coerce_int(args.get("max_items"), 15),
            )
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"tool": "codeql", "status": "error", "error": str(exc)[:500]}

    def run_owasp_scan(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return svc.run_owasp(
                manifest_path=_coerce_str(args.get("manifest_path")),
                min_cvss=_coerce_float(args.get("min_cvss")),
                max_items=_coerce_int(args.get("max_items"), 15),
            )
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"tool": "owasp-dependency-check", "status": "error", "error": str(exc)[:500]}

    def run_secret_scan(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return svc.run_secret_scan(
                target_path=_coerce_str(args.get("target_path")) or ".",
                scan_git_history=bool(args.get("scan_git_history", False)),
                max_items=_coerce_int(args.get("max_items"), 15),
            )
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"tool": "gitleaks", "status": "error", "error": str(exc)[:500]}

    def run_config_audit(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return svc.run_config_audit(
                target_path=_coerce_str(args.get("target_path")) or ".",
                check_type=_coerce_str(args.get("check_type")) or "auto",
                max_items=_coerce_int(args.get("max_items"), 15),
            )
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"tool": "config_audit", "status": "error", "error": str(exc)[:500]}

    def query_scanner_findings(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return svc.query_findings(
                tool=_coerce_str(args.get("tool")) or "all",
                cwe=_coerce_str(args.get("cwe")),
                file_path=_coerce_str(args.get("file_path")),
                min_severity=_coerce_str(args.get("min_severity")),
                max_items=_coerce_int(args.get("max_items"), 20),
            )
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"error": str(exc)[:500]}

    def explain_scanner_rule(args: dict[str, Any]) -> dict[str, Any]:
        try:
            return svc.explain_rule(
                rule_id=_coerce_str(args.get("rule_id")) or "",
                tool=_coerce_str(args.get("tool")),
            )
        except Exception as exc:  # noqa: BLE001 - tool boundary never raises
            return {"error": str(exc)[:500]}

    return {
        "run_semgrep_scan": run_semgrep_scan,
        "run_codeql_scan": run_codeql_scan,
        "run_owasp_scan": run_owasp_scan,
        "run_secret_scan": run_secret_scan,
        "run_config_audit": run_config_audit,
        "query_scanner_findings": query_scanner_findings,
        "explain_scanner_rule": explain_scanner_rule,
    }


__all__ = ["build_scanner_tool_handlers"]
