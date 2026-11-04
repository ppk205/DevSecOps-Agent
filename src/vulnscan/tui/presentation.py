"""Readable terminal summaries using retained evidence only (FR-71, QR-01/16)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from vulnscan.core.config import ScanConfig


def recovery_advice(message: str) -> str:
    text = message.lower()
    if any(word in text for word in ("report", "disk", "permission", "output")):
        return "Check artifact directory space and permissions, then export the retained run again."
    if any(word in text for word in ("scanner", "unavailable", "binary")):
        return "Check scanner availability and install the required tool before retrying."
    if any(word in text for word in ("checkout", "git", "dirty")):
        return (
            "Choose a local source folder or repository URL. Git is needed for URLs and "
            "commit pins; review Advanced options for dirty Git checkouts."
        )
    if any(
        word in text for word in ("configuration", "timeout", "threshold", "number", "timezone")
    ):
        return "Correct the named Workspace option and review the settings again."
    return "Inspect this run's Activity and retained reports before retrying."


def review_summary(checkout: str, config: ScanConfig, manifest: dict[str, Any]) -> str:
    scanners = "Semgrep + native-hunt + Gitleaks"
    if config.tools is not None:
        scanners = ", ".join(config.tools) or "No scanners selected"
    elif config.profile == "full":
        scanners += " + isolated Maven, SpotBugs/FindSecBugs, Dependency-Check"
    unversioned = manifest["commit"] == "no-revision"
    source = (
        "Repository URL"
        if manifest.get("source_kind") == "remote"
        else "Local source folder (no Git revision)"
        if unversioned
        else "Local Git checkout"
    )
    return "\n".join(
        [
            "Ready to scan",
            f"Source: {source}",
            f"Checkout: {checkout}",
            f"Commit: {manifest['commit']}",
            *(
                [f"Revision unavailable: {manifest['revision_reason']}"]
                if manifest.get("revision_reason")
                else []
            ),
            f"Java/JSP files: {len(manifest['inventory'])}",
            f"Profile: {config.profile} · {scanners}",
            f"Limits: {config.timeout} seconds · {config.max_files} files",
            f"Threshold: {config.fail_on}",
            "Checkout policy: "
            + (
                "Unversioned; file hashes recorded"
                if unversioned
                else "Local dirty contents allowed; hashes recorded"
                if config.allow_dirty
                else "Clean"
            ),
            "Laya: " + ("Advisory enabled; local model required" if config.laya else "Disabled"),
            f"Artifacts: {config.output_dir}",
            f"Display timezone: {config.timezone}",
            "Ctrl+S starts this reviewed scan. V shows the full manifest.",
        ]
    )


def finding_summary(item: dict[str, Any]) -> str:
    lines = [
        str(item.get("title", "Finding")),
        "",
        f"Severity: {item.get('severity', 'unknown')} · {item.get('cwe_category', 'unknown')}",
        f"Verification / review: {item.get('status', 'unprocessed')}",
        f"Finding: {item.get('finding_id', 'unknown')}",
        "",
        str(item.get("description", "")),
    ]
    for assessment in (item.get("metadata") or {}).get("ai_assessments", []):
        lines.extend(
            [
                "",
                "AI support explanation",
                f"Provider: {assessment.get('provider_id', 'unknown')} · Model: {assessment.get('model_id', 'unknown')}",
                f"Model proposal: {assessment.get('proposed_status', 'unknown')}",
                f"Explanation: {assessment.get('rationale', 'unavailable')}",
            ]
        )
    for observation in item.get("observations", []):
        location = observation.get("location", {})
        lines.extend(
            [
                "",
                f"Scanner: {observation.get('tool')} · Rule: {observation.get('rule_id')}",
                f"Source: {location.get('file_path')}:{location.get('line_start')}",
                str(observation.get("message", "")),
                "Source excerpt (retained by the scanner):"
                if location.get("snippet")
                else "No source excerpt was retained; use the source location above.",
            ]
        )
        if location.get("snippet"):
            lines.append(str(location["snippet"]))
    if item.get("evidence_refs"):
        lines.extend(["", "Evidence records: " + ", ".join(map(str, item["evidence_refs"]))])
    else:
        lines.extend(["", "No evidence record references are attached."])
    return "\n".join(lines)


def result_lines(result: dict[str, Any]) -> list[str]:
    lines = []
    for error in result.get("errors") or []:
        lines.extend([f"ERROR: {error}", f"Next: {recovery_advice(str(error))}"])
    for name, path in sorted((result.get("reports") or {}).items()):
        lines.append(f"Report ({name}): {path}")
    if result.get("summary_path"):
        lines.append(f"Summary: {result['summary_path']}")
    return lines


def complete_path(value: str) -> tuple[str, str]:
    directory, prefix = os.path.split(value)
    parent = Path(directory or ".")
    try:
        matches = sorted(
            entry.name
            for entry in parent.iterdir()
            if entry.is_dir() and entry.name.lower().startswith(prefix.lower())
        )
    except OSError as exc:
        return value, f"Cannot complete this path: {exc}"
    if len(matches) == 1:
        return str(parent / matches[0]) + os.sep, "Directory completed."
    if not matches:
        return value, "No matching directories."
    return value, "Matching directories: " + ", ".join(matches[:5])
