"""Turn every experiment source into one row format.

Unknown CWEs are kept as ``CWE-unknown`` rather than dropped: a finding with a
weak label is still a finding, and the ground-truth matcher decides whether it
counts. Nothing here raises on malformed tool output; a broken artifact yields
fewer rows, which the metrics report as missing coverage.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vulnscan.experiment.groundtruth import Row

_CWE_TAG = re.compile(r"external/cwe/cwe-(\d+)", re.IGNORECASE)
_CWE_TEXT = re.compile(r"cwe[-_ ]?(\d+)", re.IGNORECASE)


def _cwe(value: Any) -> str:
    """Normalise a CWE from a tag, ``CWE-89`` or a bare number; else unknown."""
    if value is None:
        return "CWE-unknown"
    text = str(value)
    tag = _CWE_TAG.search(text) or _CWE_TEXT.search(text)
    if tag is not None:
        return f"CWE-{int(tag.group(1))}"
    return "CWE-unknown"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_jsonl(path: Path) -> list[Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[Any] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _row(
    *,
    config: str,
    run: int,
    file: Any,
    line: Any,
    cwe: Any,
    severity: Any,
    cvss_vector: Any,
    stage: str,
    source_id: Any,
) -> Row | None:
    try:
        line_no = int(line)
    except (TypeError, ValueError):
        return None
    path = str(file or "").strip()
    if not path or line_no < 1:
        return None
    return Row(
        config=config,
        run=run,
        file=path,
        line=line_no,
        cwe=_cwe(cwe),
        severity=str(severity) if severity else None,
        cvss_vector=str(cvss_vector) if cvss_vector else None,
        stage=stage,  # type: ignore[arg-type]
        source_id=str(source_id),
    )


def from_scan_run(run_dir: Path, config: str) -> list[Row]:
    """Rows from ``scanner-*.json`` artifacts and the hunt output (B1–B5, B7)."""
    rows: list[Row] = []
    for artifact in sorted(Path(run_dir).glob("scanner-*.json")):
        payload = _read_json(artifact)
        if not isinstance(payload, dict):
            continue
        for observation in payload.get("observations", []) or []:
            if not isinstance(observation, dict):
                continue
            location = observation.get("location") or {}
            row = _row(
                config=config,
                run=1,
                file=location.get("file_path"),
                line=location.get("line_start"),
                cwe=observation.get("cwe_category") or observation.get("rule_id"),
                severity=observation.get("severity"),
                cvss_vector=None,
                stage="baseline",
                source_id=observation.get("observation_id") or observation.get("rule_id"),
            )
            if row is not None:
                rows.append(row)

    hunt = _read_json(Path(run_dir) / "hunt.json")
    if isinstance(hunt, dict):
        for index, candidate in enumerate(hunt.get("candidates", []) or []):
            if not isinstance(candidate, dict):
                continue
            row = _row(
                config=config,
                run=1,
                file=candidate.get("file"),
                line=candidate.get("line"),
                cwe=candidate.get("cwe"),
                severity=candidate.get("severity"),
                cvss_vector=candidate.get("cvss_vector"),
                stage="baseline",
                source_id=candidate.get("title") or f"hunt-{index}",
            )
            if row is not None:
                rows.append(row)
    return rows


def from_sarif(path: Path, config: str) -> list[Row]:
    """Rows from a CodeQL SARIF file; the CWE comes from the rule's tags."""
    payload = _read_json(Path(path))
    if not isinstance(payload, dict):
        return []
    rows: list[Row] = []
    for run in payload.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = {rule.get("id"): rule for rule in driver.get("rules", []) or [] if rule.get("id")}
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            rule = rules.get(result.get("ruleId")) or {}
            tags = (rule.get("properties") or {}).get("tags") or []
            cwe = next((tag for tag in tags if _CWE_TAG.search(str(tag))), None)
            locations = result.get("locations") or [{}]
            physical = (locations[0] or {}).get("physicalLocation") or {}
            artifact = (physical.get("artifactLocation") or {}).get("uri")
            region = physical.get("region") or {}
            row = _row(
                config=config,
                run=1,
                file=artifact,
                line=region.get("startLine"),
                cwe=cwe,
                severity=result.get("level"),
                cvss_vector=None,
                stage="baseline",
                source_id=result.get("ruleId") or "",
            )
            if row is not None:
                rows.append(row)
    return rows


def from_harness(report_json: Path, session_jsonl: Path, config: str, run: int) -> list[Row]:
    """Rows from a harness ``report.json`` plus its session log.

    ``proposed`` holds every finding the harness raised; ``after_g5`` holds the
    ones a human confirmed. A finding without a cited hop cannot be matched and
    is skipped, which the report already flags as missing evidence.
    """
    payload = _read_json(Path(report_json))
    if not isinstance(payload, dict):
        return []
    confirmed = {
        event.get("payload", {}).get("finding_id")
        for event in _read_jsonl(Path(session_jsonl))
        if isinstance(event, dict)
        and event.get("type") == "gate"
        and event.get("gate") == "G5"
        and event.get("choice") == "confirm"
    }
    rows: list[Row] = []
    for finding in payload.get("findings", []) or []:
        if not isinstance(finding, dict):
            continue
        hops = finding.get("path") or []
        if not hops:
            continue
        hop = hops[0] or {}
        for stage in ("proposed", "after_g5"):
            if stage == "after_g5" and finding.get("id") not in confirmed:
                continue
            row = _row(
                config=config,
                run=run,
                file=hop.get("file"),
                line=hop.get("line"),
                cwe=finding.get("cwe"),
                severity=None,
                cvss_vector=finding.get("cvss_vector"),
                stage=stage,
                source_id=finding.get("id") or "",
            )
            if row is not None:
                rows.append(row)
    return rows


def from_b6(jsonl: Path, config: str, run: int) -> list[Row]:
    """Rows from the model-only baseline; invalid replies carry no row."""
    rows: list[Row] = []
    for entry in _read_jsonl(Path(jsonl)):
        if not isinstance(entry, dict) or "file" not in entry:
            continue
        row = _row(
            config=config,
            run=run,
            file=entry.get("file"),
            line=entry.get("line"),
            cwe=entry.get("cwe"),
            severity=entry.get("severity"),
            cvss_vector=entry.get("cvss_vector"),
            stage="baseline",
            source_id=entry.get("title") or entry.get("source_id") or "",
        )
        if row is not None:
            rows.append(row)
    return rows
