"""Gated tool registry the model can call.

Every tool either asks a human first (G1–G7) or runs inside a batch the human
already approved. No tool runs a shell command, reaches the network beyond the
model API, or writes outside the fix worktree.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnscan.decisions.config import LayaConfig
from vulnscan.providers.credentials import redact_json

from .audit import SessionLog
from .evidence import check_citations, score_cvss4
from .fixes import FixError, _validate_id, apply_fix, changed_lines, diff_hunks, rescan_fix
from .gates import Gate, GateDecision, GateKeeper, GateRequest
from .messages import ToolCall
from .scanning import extract_candidates, inventory, lookup_route
from .triage import triage_candidates
from .workspace import Candidate, FixProposal, Hop, PathEscape, ProposedFinding, Workspace

__all__ = ["REGISTRY", "ToolContext", "ToolSpec", "run_tool", "schemas"]


@dataclass
class ToolContext:
    """Everything a tool handler may touch."""

    ws: Workspace
    gates: GateKeeper
    log: SessionLog
    laya_config: LayaConfig
    laya_agent: Any | None = None
    worktrees: Path = field(default_factory=lambda: Path(".devsec/worktrees"))


@dataclass
class ToolSpec:
    """One model-callable tool."""

    name: str
    description: str
    parameters: dict[str, Any]
    gate: Gate | None
    handler: Callable[[ToolContext, dict[str, Any]], dict[str, Any]]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _ask(
    ctx: ToolContext,
    gate: Gate,
    title: str,
    detail: str,
    payload: dict[str, Any],
    recommendation: str = "",
) -> GateDecision:
    return ctx.gates.ask(GateRequest(gate, title, detail, payload, recommendation))


def _refusal(gate: Gate, decision: GateDecision) -> dict[str, Any]:
    status = "rejected" if decision.choice == "reject" else "undecided"
    return {"status": status, "gate": gate.value, "reason": decision.reason or decision.choice}


def _plan(ctx: ToolContext) -> dict[str, Any]:
    if ctx.ws.plan is None:
        raise ValueError("no approved scan plan; call propose_scan_plan first")
    return ctx.ws.plan


def _require_batch(ctx: ToolContext) -> list[str]:
    if not ctx.ws.open_batch:
        raise ValueError("no approved investigation batch; call begin_investigation first")
    return sorted(ctx.ws.open_batch)


def _candidate(ctx: ToolContext, candidate_id: str) -> Candidate:
    candidate = ctx.ws.candidates.get(candidate_id)
    if candidate is None:
        raise ValueError(f"unknown candidate: {candidate_id}")
    return candidate


def _untrusted(path: str, body: str) -> str:
    return f'<untrusted_code path="{path}">\n{body}\n</untrusted_code>'


def _hops(raw: Any) -> list[Hop]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("path must be a non-empty list of {file, line, code, note}")
    hops: list[Hop] = []
    for item in raw:
        if not isinstance(item, dict) or "file" not in item or "line" not in item:
            raise ValueError("each path hop needs file, line and code")
        hops.append(
            Hop(
                file=str(item["file"]),
                line=int(item["line"]),
                code=str(item.get("code") or ""),
                note=str(item.get("note") or ""),
            )
        )
    return hops


def _ids(raw: Any) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError("candidate_ids must be a list of strings")
    return [str(item) for item in raw]


# ---------------------------------------------------------------------------
# handlers
# ---------------------------------------------------------------------------


def _propose_scan_plan(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    scope = [str(item) for item in args["scope"]]
    classes = [str(item) for item in args["classes"]]
    decision = _ask(
        ctx,
        Gate.G1_PLAN,
        "Approve the scan plan",
        f"Scope: {', '.join(scope)}\nVulnerability classes: {', '.join(classes)}",
        {"scope": scope, "classes": classes},
        "The model proposes this plan before any file is read.",
    )
    if not decision.approved:
        return _refusal(Gate.G1_PLAN, decision)
    plan = {
        "scope": [str(item) for item in decision.edits.get("scope", scope)],
        "classes": [str(item) for item in decision.edits.get("classes", classes)],
    }
    ctx.ws.plan = plan
    return {"status": "approved", "plan": plan}


def _inventory(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    _plan(ctx)
    globs = [str(item) for item in args["globs"]]
    decision = _ask(
        ctx,
        Gate.G2_SCAN,
        "Run the file inventory",
        f"Globs: {', '.join(globs)}",
        {"globs": globs},
        "Read-only listing; no file contents are sent to the model.",
    )
    if not decision.approved:
        return _refusal(Gate.G2_SCAN, decision)
    effective = [str(item) for item in decision.edits.get("globs", globs)]
    return {"files": inventory(ctx.ws, effective)}


def _extract_candidates(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    plan = _plan(ctx)
    classes = [str(item) for item in args.get("classes") or plan["classes"]]
    paths = [str(item) for item in args.get("paths") or plan["scope"]]
    decision = _ask(
        ctx,
        Gate.G2_SCAN,
        "Run candidate extraction",
        f"Paths: {', '.join(paths)}\nClasses: {', '.join(classes)}",
        {"classes": classes, "paths": paths},
        "Read-only source-sink pass over the target checkout.",
    )
    if not decision.approved:
        return _refusal(Gate.G2_SCAN, decision)
    found = extract_candidates(
        ctx.ws,
        [str(item) for item in decision.edits.get("classes", classes)],
        [str(item) for item in decision.edits.get("paths", paths)],
    )
    return {
        "candidates": [
            {"id": c.id, "cwe": c.cwe, "kind": c.kind, "file": c.file, "line": c.line}
            for c in found
        ]
    }


def _laya_triage(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ids = _ids(args.get("candidate_ids") or sorted(ctx.ws.candidates))
    cands = [_candidate(ctx, candidate_id) for candidate_id in ids]
    decision = _ask(
        ctx,
        Gate.G2_SCAN,
        "Run Laya triage",
        (
            f"Skip Laya for {len(cands)} candidate(s): Laya disabled for S1."
            if ctx.laya_config.mode == "off"
            else f"{len(cands)} candidate(s) will be routed by the local Laya model on the CPU."
        ),
        {"candidate_ids": ids},
        "Laya narrows what the model reads; it never sets a finding's status.",
    )
    if not decision.approved:
        return _refusal(Gate.G2_SCAN, decision)
    chosen = _ids(decision.edits.get("candidate_ids", ids))
    cands = [_candidate(ctx, candidate_id) for candidate_id in chosen]
    routes = triage_candidates(cands, ctx.laya_config, ctx.laya_agent)
    return {
        "routes": {
            candidate_id: {
                "route": route.route,
                "confidence": route.confidence,
                "status": route.status.value,
                "reasons": route.reasons,
            }
            for candidate_id, route in routes.items()
        }
    }


def _select_candidates(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ids = _ids(args["candidate_ids"])
    for candidate_id in ids:
        _candidate(ctx, candidate_id)
    decision = _ask(
        ctx,
        Gate.G3_TRIAGE,
        "Choose the candidates to investigate",
        str(args.get("reason") or ""),
        {
            "candidates": [
                {
                    "id": candidate_id,
                    "cwe": ctx.ws.candidates[candidate_id].cwe,
                    "kind": ctx.ws.candidates[candidate_id].kind,
                    "file": ctx.ws.candidates[candidate_id].file,
                    "line": ctx.ws.candidates[candidate_id].line,
                    "laya_route": ctx.ws.candidates[candidate_id].laya_route,
                    "laya_confidence": ctx.ws.candidates[candidate_id].laya_confidence,
                }
                for candidate_id in ids
            ]
        },
        "Laya routes are advisory; the human decides what gets investigated.",
    )
    if not decision.approved:
        return _refusal(Gate.G3_TRIAGE, decision)
    chosen = _ids(decision.edits.get("candidate_ids", ids))
    for candidate in ctx.ws.candidates.values():
        candidate.selected = candidate.id in chosen
    return {"status": "approved", "candidate_ids": chosen}


def _begin_investigation(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ids = _ids(args["candidate_ids"])

    def validate(candidate_ids: list[str]) -> None:
        for candidate_id in candidate_ids:
            candidate = _candidate(ctx, candidate_id)
            if not candidate.selected:
                raise ValueError(f"candidate {candidate_id} was not selected at G3")
            if candidate.laya_route is None:
                raise ValueError(f"candidate {candidate_id} needs Laya triage before investigation")

    validate(ids)
    decision = _ask(
        ctx,
        Gate.G4_INVESTIGATE,
        "Open an investigation batch",
        f"{len(ids)} candidate(s) will be read line by line.\nEvery read is logged.",
        {"candidate_ids": ids},
        "Reads inside an approved batch run without a prompt each.",
    )
    if not decision.approved:
        return _refusal(Gate.G4_INVESTIGATE, decision)
    chosen = _ids(decision.edits.get("candidate_ids", ids))
    validate(chosen)
    ctx.ws.open_batch = set(chosen)
    ctx.ws.batch_tokens = 0
    return {"status": "approved", "candidate_ids": chosen}


def _read_file(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    _require_batch(ctx)
    path = str(args["path"])
    start = int(args.get("start") or 1)
    end = args.get("end")
    body = ctx.ws.read(path, start, int(end) if end is not None else None)
    return {"content": _untrusted(path, body)}


def _grep(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    _require_batch(ctx)
    pattern = str(args["pattern"])
    glob = str(args.get("glob") or "**/*")
    hits = ctx.ws.grep(pattern, glob)
    return {"hits": [_untrusted(f"{path}:{line}", f"{line}: {text}") for path, line, text in hits]}


def _lookup_route(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    _require_batch(ctx)
    return lookup_route(ctx.ws, str(args["query"]))


def _propose_finding(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    _require_batch(ctx)
    candidate_id = str(args["candidate_id"])
    if candidate_id not in ctx.ws.open_batch:
        raise ValueError(f"candidate {candidate_id} is not in the open investigation batch")
    _candidate(ctx, candidate_id)
    hops = _hops(args["path"])

    evidence_errors = check_citations(ctx.ws, hops)
    vector = str(args["cvss_vector"])
    score: float | None
    try:
        score = score_cvss4(vector)
    except ValueError as exc:
        evidence_errors.append(str(exc))
        score = None

    finding = ProposedFinding(
        id="F" + candidate_id,
        candidate_id=candidate_id,
        title=str(args["title"]),
        cwe=str(args["cwe"]),
        path=hops,
        explanation=str(args["explanation"]),
        cvss_vector=vector,
        cvss_score=score,
        evidence_errors=evidence_errors,
        tokens=ctx.ws.batch_tokens,
    )
    decision = _ask(
        ctx,
        Gate.G5_FINDING,
        f"Decide finding {finding.id}: {finding.title}",
        f"{finding.cwe} · CVSS score {score if score is not None else 'unavailable'}\n"
        f"{len(hops)} cited hop(s); {len(evidence_errors)} evidence problem(s).",
        {
            "finding_id": finding.id,
            "cwe": finding.cwe,
            "cvss_vector": vector,
            "cvss_score": score,
            "evidence_errors": evidence_errors,
            "path": [{"file": hop.file, "line": hop.line} for hop in hops],
        },
        "Only a human sets a finding's final status.",
    )
    statuses = {"confirm": "confirmed", "reject": "rejected", "need_more": "need_more"}
    if decision.choice in statuses:
        finding.status = statuses[decision.choice]
        finding.decided_by = decision.person
        finding.reason = decision.reason
    ctx.ws.findings[finding.id] = finding
    return {
        "finding_id": finding.id,
        "status": finding.status,
        "cvss_score": finding.cvss_score,
        "evidence_errors": finding.evidence_errors,
    }


FIX_WINDOW = 15
MAX_FIX_LINES = 80


def _check_fix_scope(finding: ProposedFinding, diff: str) -> None:
    """Refuse a diff that leaves the finding's cited code.

    A fix is a suggestion about one vulnerability, not a refactor: it may only
    touch the hop files, within ``FIX_WINDOW`` lines of a cited hop, and change
    at most ``MAX_FIX_LINES`` lines. Raising here keeps the refusal out of the
    audit log's G6 record, because no gate was ever asked.
    """
    hops = finding.path
    files = {hop.file for hop in hops}
    hunks = diff_hunks(diff)
    changed = changed_lines(diff)
    if changed > MAX_FIX_LINES:
        locations = ", ".join(f"{file}:{start}-{end}" for file, start, end in hunks)
        raise ValueError(
            f"fix changes {changed} lines in {locations}; the limit is {MAX_FIX_LINES} "
            f"(finding {finding.id})"
        )
    for file, start, end in hunks:
        if file not in files:
            raise ValueError(f"fix touches {file}, which is not cited by finding {finding.id}")
        uncovered = start
        for low, high in sorted(
            (hop.line - FIX_WINDOW, hop.line + FIX_WINDOW) for hop in hops if hop.file == file
        ):
            if low > uncovered:
                break
            if high >= uncovered:
                uncovered = high + 1
        if uncovered <= end:
            raise ValueError(
                f"fix touches {file}:{start}-{end}, more than {FIX_WINDOW} lines "
                f"from any cited line of finding {finding.id}"
            )


def _propose_fix(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(args["finding_id"])
    _validate_id(finding_id)
    finding = ctx.ws.findings.get(finding_id)
    if finding is None:
        raise ValueError(f"unknown finding: {finding_id}")
    if finding.status != "confirmed":
        raise ValueError(f"finding {finding_id} is not confirmed; a fix needs a human confirmation")

    _check_fix_scope(finding, str(args["diff"]))
    for file, _, _ in diff_hunks(str(args["diff"])):
        ctx.ws.resolve(file)

    fix = FixProposal(
        id="X" + finding_id,
        finding_id=finding_id,
        diff=str(args["diff"]),
        test_hint=str(args.get("test_hint") or ""),
    )
    unversioned = ctx.ws.commit == "unversioned"
    decision = _ask(
        ctx,
        Gate.G6_FIX,
        (
            "Export patch (target is not a git repository)"
            if unversioned
            else f"Apply the fix for {finding_id} on a separate branch?"
        ),
        str(
            args.get("test_hint")
            or (
                "The model proposes this diff; nothing is written until you apply."
                if not unversioned
                else "The model proposes this diff; it is saved as a patch file, never applied."
            )
        ),
        {"fix_id": fix.id, "finding_id": finding_id, "diff": fix.diff},
        (
            "The harness exports to .devsec/patches; the target is never modified."
            if unversioned
            else "The harness writes only inside .devsec/worktrees and never commits."
        ),
    )
    if decision.choice == "apply":
        apply_fix(ctx.ws, fix, ctx.worktrees)
    elif decision.choice == "reject":
        fix.status = "rejected"
    elif decision.choice == "defer":
        fix.status = "deferred"
    ctx.ws.fixes[fix.id] = fix
    return {"fix_id": fix.id, "status": fix.status, "branch": fix.branch}


def _rescan(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    def eligible(finding_id: Any) -> FixProposal:
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError("finding_id must be a non-empty string")
        _validate_id(finding_id)
        fix = ctx.ws.fixes.get("X" + finding_id)
        if fix is None or fix.finding_id != finding_id:
            raise ValueError(f"no fix proposed for {finding_id}")
        if fix.status != "applied" and not (
            fix.status == "exported" and ctx.ws.commit == "unversioned"
        ):
            raise ValueError(f"fix for {finding_id} is {fix.status}, not applied")
        return fix

    finding_id = args["finding_id"]
    fix = eligible(finding_id)
    decision = _ask(
        ctx,
        Gate.G7_RESCAN,
        f"Re-scan the fixed files for {finding_id}?",
        f"Branch {fix.branch}; the original candidate kind is checked again.",
        {"finding_id": finding_id, "branch": fix.branch},
        "Re-scan decides nothing by itself; mark fixed only if the candidate is gone.",
    )
    if not decision.approved:
        return _refusal(Gate.G7_RESCAN, decision)
    fix = eligible(decision.edits.get("finding_id", finding_id))
    return {"result": rescan_fix(ctx.ws, fix, ctx.worktrees)}


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


_STR = {"type": "string"}
_STRS = {"type": "array", "items": {"type": "string"}}
_INT = {"type": "integer"}

REGISTRY: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            "propose_scan_plan",
            "Ask a human (G1) to approve what you intend to scan, then return the plan.",
            _schema(
                {"scope": _STRS, "classes": _STRS},
                ["scope", "classes"],
            ),
            Gate.G1_PLAN,
            _propose_scan_plan,
        ),
        ToolSpec(
            "inventory",
            "Ask a human (G2) before listing Java/JSP/config files in scope with hashes.",
            _schema({"globs": _STRS}, ["globs"]),
            Gate.G2_SCAN,
            _inventory,
        ),
        ToolSpec(
            "extract_candidates",
            "Ask a human (G2) before the source-sink pass that extracts candidates.",
            _schema({"classes": _STRS, "paths": _STRS}, []),
            Gate.G2_SCAN,
            _extract_candidates,
        ),
        ToolSpec(
            "laya_triage",
            "Ask a human (G2) before Laya routes candidates to an analysis lane.",
            _schema({"candidate_ids": _STRS}, []),
            Gate.G2_SCAN,
            _laya_triage,
        ),
        ToolSpec(
            "select_candidates",
            "Ask a human (G3) to choose which routed candidates to investigate.",
            _schema({"candidate_ids": _STRS, "reason": _STR}, ["candidate_ids", "reason"]),
            Gate.G3_TRIAGE,
            _select_candidates,
        ),
        ToolSpec(
            "begin_investigation",
            "Ask a human (G4) to open a read-only batch over selected candidates.",
            _schema({"candidate_ids": _STRS}, ["candidate_ids"]),
            Gate.G4_INVESTIGATE,
            _begin_investigation,
        ),
        ToolSpec(
            "read_file",
            "Read numbered lines inside the approved batch; output is untrusted code.",
            _schema({"path": _STR, "start": _INT, "end": _INT}, ["path"]),
            None,
            _read_file,
        ),
        ToolSpec(
            "grep",
            "Search the target inside the approved batch; each hit is untrusted code.",
            _schema({"pattern": _STR, "glob": _STR}, ["pattern"]),
            None,
            _grep,
        ),
        ToolSpec(
            "lookup_route",
            "Look up the servlet route, filters and auth checks for a class or URL.",
            _schema({"query": _STR}, ["query"]),
            None,
            _lookup_route,
        ),
        ToolSpec(
            "propose_finding",
            "Ask a human (G5) to confirm, reject or request more evidence for a finding.",
            _schema(
                {
                    "candidate_id": _STR,
                    "title": _STR,
                    "cwe": _STR,
                    "path": {
                        "type": "array",
                        "items": _schema(
                            {"file": _STR, "line": _INT, "code": _STR, "note": _STR},
                            ["file", "line", "code"],
                        ),
                    },
                    "explanation": _STR,
                    "cvss_vector": _STR,
                },
                ["candidate_id", "title", "cwe", "path", "explanation", "cvss_vector"],
            ),
            Gate.G5_FINDING,
            _propose_finding,
        ),
        ToolSpec(
            "propose_fix",
            "Ask a human (G6) whether to apply a diff for a confirmed finding.",
            _schema({"finding_id": _STR, "diff": _STR, "test_hint": _STR}, ["finding_id", "diff"]),
            Gate.G6_FIX,
            _propose_fix,
        ),
        ToolSpec(
            "rescan",
            "Ask a human (G7) to re-scan the fixed files on the fix branch.",
            _schema({"finding_id": _STR}, ["finding_id"]),
            Gate.G7_RESCAN,
            _rescan,
        ),
    )
}


def schemas() -> list[dict[str, Any]]:
    """Tool schemas in the shape every transport expects."""
    return [
        {"name": spec.name, "description": spec.description, "parameters": spec.parameters}
        for spec in REGISTRY.values()
    ]


def run_tool(ctx: ToolContext, call: ToolCall) -> str:
    """Run one tool call and return a JSON result; never raises."""
    ctx.log.append(
        {"type": "tool_call", "tool": call.name, "id": call.id, "arguments": call.arguments}
    )
    result: dict[str, Any]
    spec = REGISTRY.get(call.name)
    if spec is None:
        result = {"error": "unknown tool"}
    elif "_unparsed" in call.arguments:
        result = {"error": "invalid arguments: the arguments were not valid JSON"}
    else:
        required = spec.parameters.get("required") or []
        missing = [key for key in required if key not in call.arguments]
        if missing:
            result = {"error": f"invalid arguments: missing {', '.join(missing)}"}
        else:
            try:
                result = spec.handler(ctx, call.arguments)
            except (PathEscape, FixError, ValueError, KeyError, TypeError, OSError) as exc:
                result = {"error": str(exc)}
            except Exception as exc:  # noqa: BLE001 - a tool must never break the loop
                result = {"error": f"{type(exc).__name__}: {exc}"}
    ctx.log.append({"type": "tool_result", "tool": call.name, "id": call.id, "result": result})
    return redact_json(result)
