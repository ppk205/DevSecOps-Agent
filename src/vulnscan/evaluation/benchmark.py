"""Read-only benchmark projection from retained scan evidence (FR-63)."""

from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from vulnscan.core.security import sanitize

BenchmarkRun = tuple[int, str, dict[str, Any], dict[str, Any]]
_AI_SCENARIOS = {"A1", "A2", "A3"}
_COVERAGE_FIELDS = ("eligible_units", "analyzed_units", "skipped_units")


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]] | None:
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    return None


def _count(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _number(value: Any) -> float | None:
    return (
        float(value)
        if type(value) in (int, float) and math.isfinite(value) and value >= 0
        else None
    )


def _label(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError:
            return None
        if timestamp.tzinfo is not None:
            return timestamp
    return None


def _stage_durations(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    started: dict[str, datetime | None] = {}
    durations = {}
    for event in events:
        name = _label(event.get("stage"))
        status = _label(event.get("status"))
        if not name or not status or name in {"model_call", "model_tool"}:
            continue
        timestamp = _timestamp(event.get("timestamp"))
        beginning = None
        if status == "running":
            started[name] = timestamp
        else:
            beginning = started.pop(name, None)
        elapsed = (timestamp - beginning).total_seconds() if timestamp and beginning else None
        durations[name] = {
            "name": name,
            "status": status,
            "duration_seconds": _number(elapsed),
        }
    return list(durations.values())


def _scenario(config: dict[str, Any]) -> str:
    if config.get("mode") == "hunt":
        return "A4"
    if config.get("mode") != "deterministic":
        return "custom"
    review, report, laya = (config.get(key) for key in ("ai_review", "ai_report", "laya"))
    if review is False and report is False and laya is False:
        return "A0"
    if review is True and report is True:
        limit = _count(config.get("max_ai_findings"))
        if limit == 10 and laya is False:
            return "A1"
        if limit == 5 and type(laya) is bool:
            return "A3" if laya else "A2"
    return "custom"


def _tokens(calls: list[dict[str, Any]], field: str) -> int | None:
    if not calls:
        return None
    total = 0
    for call in calls:
        usage = _object(call.get("usage"))
        value = _count(usage.get(field))
        if value is None and field == "total_tokens":
            prompt = _count(usage.get("prompt_tokens"))
            completion = _count(usage.get("completion_tokens"))
            if prompt is not None and completion is not None:
                value = prompt + completion
        if value is None:
            return None
        total += value
    return total


def _coverage(scanners: list[dict[str, Any]]) -> dict[str, Any] | None:
    signature = {}
    for scanner in scanners:
        tool = _label(scanner.get("tool"))
        counts = tuple(_count(scanner.get(field)) for field in _COVERAGE_FIELDS)
        records = _objects(scanner.get("coverage_records"))
        if (
            tool is None
            or tool in signature
            or scanner.get("status") != "completed"
            or scanner.get("errors")
            or _count(scanner.get("failed_units")) not in (None, 0)
            or None in counts
            or records is None
            or (not records and any(counts))
        ):
            return None
        units = []
        for item in records:
            path = _label(item.get("unit_path"))
            status = _label(item.get("status"))
            eligible = item.get("eligible")
            if (
                not path
                or not status
                or type(eligible) is not bool
                or (eligible and status not in {"analyzed", "unsupported", "not_eligible"})
            ):
                return None
            units.append((path, _label(item.get("unit_language")) or "", eligible, status))
        signature[tool] = (
            counts,
            sorted(units),
            _label(scanner.get("tool_version")),
            _label(scanner.get("adapter_version")),
        )
    return signature


def _row(run: BenchmarkRun) -> tuple[dict[str, Any], dict[str, Any], str | None]:
    run_id, status, spec, snapshot = run
    metadata = _object(spec.get("metadata"))
    config = _object(snapshot.get("configuration")) or _object(metadata.get("configuration"))
    scenario = _scenario(config)
    complete = status == "completed" and _count(snapshot.get("exit_code")) in (0, 1)
    offline = scenario == "A0" and complete
    stage_events = _objects(snapshot.get("stages")) or []
    stages = {
        stage.get("stage"): stage for stage in stage_events if isinstance(stage.get("stage"), str)
    }
    calls = _objects(snapshot.get("model_calls")) or []
    usage = _object(snapshot.get("ai_usage"))
    identities = {
        (provider, model)
        for call in calls
        if call.get("status") == "completed"
        and (provider := _label(call.get("provider")))
        and (model := _label(call.get("model")))
    }
    observed_identity = next(iter(identities)) if len(identities) == 1 else (None, None)
    configured_identity = (
        _label(config.get("provider_profile")) or observed_identity[0],
        _label(config.get("provider_model")) or observed_identity[1],
    )
    scanners = _objects(snapshot.get("scanner_results")) or []
    coverage = _coverage(scanners)
    selected = _objects(spec.get("tools")) or []
    selected_tools = {_label(item.get("tool")) for item in selected}
    routing = _objects(snapshot.get("routing"))
    devices = {
        device
        for result in routing or []
        if result.get("decision_status") == "completed"
        and (device := _label(result.get("device"))) not in (None, "unknown", "auto")
    }
    commit = _label(snapshot.get("commit")) or _label(spec.get("target_commit_sha"))
    target = _label(spec.get("target_repository_url"))
    manifest = _object(snapshot.get("manifest"))
    files = manifest.get("files")
    context = {
        "target": target,
        "commit": commit,
        "files": files,
        "scanner_selection": sorted(tool for tool in selected_tools if tool is not None),
        "coverage": coverage,
        "application_version": _label(snapshot.get("application_version")),
        "configured_ai": configured_identity,
        "observed_ai": identities,
    }
    requests = _count(usage.get("requests"))
    completed_requests = _count(usage.get("completed_requests"))
    failed_requests = _count(usage.get("failed_requests"))
    attempts = _count(usage.get("http_attempts"))
    max_model_requests = _count(usage.get("max_model_requests"))
    if max_model_requests is None:
        max_model_requests = _count(config.get("max_model_requests"))
    review_stage = stages.get("targeted_deep_analysis", {})
    final = _object(snapshot.get("final_report"))
    laya_stage = stages.get("laya_batch_routing", {})
    reviewed = _objects(snapshot.get("assessments"))
    validated = _objects(snapshot.get("validation_decisions"))
    ai_incomplete = scenario in _AI_SCENARIOS and (
        not all(observed_identity)
        or requests != len(calls)
        or completed_requests != len(calls)
        or failed_requests != 0
        or review_stage.get("status") != "completed"
        or final.get("status") != "completed"
        or final.get("ai_written") is not True
    )
    limitations = []
    if ai_incomplete:
        limitations.append(
            "AI review or report was incomplete. Time and attempts describe the observed execution."
        )
    if scenario == "A3" and (
        laya_stage.get("status") != "completed"
        or not routing
        or not devices
        or any(result.get("decision_status") != "completed" for result in routing)
    ):
        limitations.append("Laya routing was incomplete or its execution evidence is missing.")
    complete_usage = not ai_incomplete and (attempts is None or attempts == len(calls))
    row = {
        "run_id": run_id,
        "scenario": scenario,
        "profile": _label(config.get("profile")),
        "commit": commit,
        "model": observed_identity[1] or _label(final.get("model")) or configured_identity[1],
        "review_limit": _count(config.get("max_ai_findings")),
        "status": status,
        "gate": _label(snapshot.get("gate")),
        "duration_seconds": _number(snapshot.get("duration_seconds")),
        "stage_durations": _stage_durations(stage_events),
        "limitations": limitations,
        "scanners": [
            {
                "tool": _label(scanner.get("tool")),
                "status": _label(scanner.get("status")),
                **{name: _count(scanner.get(name)) for name in _COVERAGE_FIELDS},
            }
            for scanner in scanners
        ],
        "requests": 0 if offline and requests is None else requests,
        "http_attempts": 0 if offline and attempts is None else attempts,
        "max_model_requests": max_model_requests,
        "completed_requests": 0 if offline and completed_requests is None else completed_requests,
        "failed_requests": 0 if offline and failed_requests is None else failed_requests,
        **{
            field: _tokens(calls, field) if complete_usage else None
            for field in ("prompt_tokens", "completion_tokens", "total_tokens")
        },
        "reviewed": (
            sum("error" not in _object(assessment.get("metadata")) for assessment in reviewed)
            if reviewed is not None
            else 0
            if offline
            else None
        ),
        "validated": len(validated) if validated is not None else 0 if offline else None,
        "laya_devices": sorted(device for device in devices if device is not None),
        "laya_timeouts": (
            sum(result.get("error_code") == "timeout" for result in routing)
            if routing
            and all(
                "error_code" in result or result.get("decision_status") == "completed"
                for result in routing
            )
            else 0
            if config.get("laya") is False
            else None
        ),
    }
    reason = None
    if scenario in {"A4", "custom"}:
        reason = "This scenario is outside the A0–A3 pilot."
    elif not complete:
        reason = "The scan did not complete successfully."
    elif not target or commit in (None, "no-revision") or not isinstance(files, dict):
        reason = "The target revision or snapshot is missing."
    elif not selected_tools or coverage is None or selected_tools != coverage.keys():
        reason = "Scanner selection or complete coverage evidence is missing."
    elif scenario in _AI_SCENARIOS and not all(configured_identity):
        reason = "The configured AI provider or model is missing."
    elif scenario in _AI_SCENARIOS and len(identities) > 1:
        reason = "The run used more than one observed AI provider or model."
    elif scenario == "A0" and (calls or requests or attempts or final.get("ai_written")):
        reason = "Model activity was recorded during the scanner-only scenario."
    return row, context, reason


def _savings(reference: Any, measured: Any) -> float | None:
    if reference is None or reference == 0 or measured is None:
        return None
    return float((reference - measured) / reference * 100)


def compare_benchmark(runs: Sequence[BenchmarkRun]) -> dict[str, Any]:
    indexed = [_row(run) for run in runs]
    candidates = [entry for entry in indexed if entry[0]["scenario"] == "A1"]
    reference = next((entry for entry in candidates if entry[2] is None), None)
    if reference is None and candidates:
        reference = candidates[0]
    rows = []
    for row, context, reason in indexed:
        if reference is None:
            reason = reason or "Select an A1 run as the pilot reference."
            reference_row: dict[str, Any] = {}
        else:
            reference_row, reference_context, reference_reason = reference
            if reason is None:
                if reference_reason:
                    reason = f"A1 reference is ineligible. {reference_reason}"
                elif any(
                    context[key] != reference_context[key] for key in ("target", "commit", "files")
                ):
                    reason = "The target revision or snapshot differs from A1."
                elif context["scanner_selection"] != reference_context["scanner_selection"]:
                    reason = "The selected scanners differ from A1."
                elif context["application_version"] != reference_context["application_version"]:
                    reason = "The application version differs from A1."
                elif context["coverage"] != reference_context["coverage"]:
                    reason = "Observed scanner coverage or versions differ from A1."
                elif row["scenario"] in _AI_SCENARIOS:
                    if context["configured_ai"] != reference_context["configured_ai"]:
                        reason = "The configured AI provider or model differs from A1."
                    elif (
                        context["observed_ai"]
                        and reference_context["observed_ai"]
                        and context["observed_ai"] != reference_context["observed_ai"]
                    ):
                        reason = "The observed AI provider or model differs from A1."
        row["comparable"] = reason is None
        row["comparison_reason"] = reason
        row["savings"] = {
            name: _savings(reference_row.get(field), row.get(field)) if reason is None else None
            for name, field in (
                ("duration_percent", "duration_seconds"),
                ("requests_percent", "http_attempts"),
                ("tokens_percent", "total_tokens"),
            )
        }
        rows.append(row)
    return {
        "reference_run_id": reference[0]["run_id"] if reference else None,
        "rows": sanitize(rows),
    }
