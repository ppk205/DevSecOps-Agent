"""Shared security gate: execution and coverage failures take precedence."""

from __future__ import annotations

from typing import Any

from vulnscan.contracts import Finding, FindingStatus, ScannerResult, Severity

RANK = {
    s: n
    for n, s in enumerate(
        [
            Severity.UNDETERMINED,
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
    )
}


def effective_severity(finding: Finding) -> Severity:
    validated = finding.metadata.get("validated_assessment", {})
    if validated.get("validated_by") == "independent-validator":
        return Severity(validated["severity"])
    return max(
        (o.severity for o in finding.observations), key=RANK.__getitem__, default=finding.severity
    )


def gate(
    findings: list[Finding],
    results: list[ScannerResult],
    required: list[str],
    fail_on: str,
    coverage_errors: list[str],
    *,
    cancelled: bool = False,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    failures = list(errors or []) + coverage_errors
    by_tool = {r.tool.value: r for r in results}
    for tool in required:
        if tool not in by_tool or not by_tool[tool].is_complete:
            failures.append(f"{tool}: required scanner did not complete successfully")
    active = [
        f
        for f in findings
        if not (
            f.status == FindingStatus.REJECTED
            and f.metadata.get("validation_decision", {}).get("decided_by")
            == "independent-validator"
            and f.metadata.get("validation_decision", {}).get("new_status") == "rejected"
        )
    ]
    unknown = [f.finding_id for f in active if effective_severity(f) == Severity.UNDETERMINED]
    exceeded = (
        []
        if fail_on == "none"
        else [
            f.finding_id for f in active if RANK[effective_severity(f)] >= RANK[Severity(fail_on)]
        ]
    )
    code = 130 if cancelled else 2 if failures else 1 if exceeded else 0
    return {
        "exit_code": code,
        "gate": "passed" if code == 0 else "failed",
        "threshold": fail_on,
        "exceeded": exceeded,
        "unknown_severity": unknown,
        "errors": failures,
    }
