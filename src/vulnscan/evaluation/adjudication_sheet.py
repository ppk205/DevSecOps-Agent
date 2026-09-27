"""Render the 29 advisory-routed findings as a reviewable adjudication sheet.

Each row carries the exact source line Laya saw, so a human can label
``expected_route`` by reading code rather than by guessing from a rule name.
This tool renders; it never labels. Only a person adjudicates.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

CONTEXT_LINES = 6


def _repo_path(file_path: str, repo_root: Path) -> Path | None:
    """Resolve an absolute scan path back into the checkout, if it is there.

    A scan records absolute paths from whichever machine ran the scanner, so
    the checkout prefix has to be stripped before the path can be re-resolved.
    """
    if not file_path:
        return None
    raw = Path(file_path)
    candidates: list[Path] = []
    if raw.is_absolute():
        parts = raw.parts
        if "src" in parts:
            idx = len(parts) - 1 - parts[::-1].index("src")
            candidates.append(repo_root.joinpath(*parts[idx:]))
        candidates.append(raw)
    else:
        candidates.append(repo_root / raw)
        candidates.append(raw)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _source_excerpt(
    file_path: str, line_start: int | None, repo_root: Path, context: int = CONTEXT_LINES
) -> str | None:
    """The scanned line plus a little context, or None if unreachable."""
    path = _repo_path(file_path, repo_root)
    if path is None or not line_start:
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = max(0, line_start - 1 - context)
    end = min(len(lines), line_start + context)
    out: list[str] = []
    for i in range(start, end):
        marker = ">>" if i == line_start - 1 else "  "
        out.append(f"{marker} {i + 1:>5} | {lines[i]}")
    return "\n".join(out)


def build_sheet(
    scan: dict[str, Any],
    repo_root: Path,
    confidence_key: str = "recommended_action",
) -> list[dict[str, Any]]:
    """One reviewable entry per finding, ordered by route then CWE."""
    payloads = scan.get("advisory_routing", {}).get("payloads", [])
    findings = {f["finding_id"]: f for f in scan.get("findings", [])}

    rows: list[dict[str, Any]] = []
    for payload in payloads:
        finding_id = str(payload.get("finding_id", ""))
        finding = findings.get(finding_id, {})
        obs = (finding.get("observations") or [{}])[0]
        location = obs.get("location") or {}
        answer = (payload.get("answers") or {}).get(confidence_key) or {}

        file_path = str(location.get("file_path") or "")
        rows.append(
            {
                "finding_id": finding_id,
                "cwe": finding.get("cwe_category"),
                "severity": finding.get("severity"),
                "laya_route": payload.get("route"),
                "laya_confidence": answer.get("confidence"),
                "laya_probs": answer.get("probabilities"),
                "needs_human_review": (
                    (payload.get("answers") or {}).get("needs_human_review") or {}
                ).get("noul"),
                "evidence_sufficiency": (
                    (payload.get("answers") or {}).get("evidence_sufficiency") or {}
                ).get("score"),
                "rule_id": obs.get("rule_id"),
                "file": file_path,
                "line": location.get("line_start"),
                "message": (obs.get("message") or "")[:160],
                "expected_route": None,
                "source": _source_excerpt(
                    file_path, location.get("line_start"), repo_root
                ),
            }
        )

    rows.sort(key=lambda r: (str(r["laya_route"]), str(r["cwe"]), str(r["finding_id"])))
    return rows


def render_text(rows: Sequence[dict[str, Any]], limit: int | None = None) -> str:
    """Human-readable adjudication sheet."""
    out: list[str] = []
    shown = rows if limit is None else rows[:limit]

    for i, row in enumerate(shown, start=1):
        out.append("=" * 78)
        out.append(
            f"[{i}] {row['finding_id']}  {row['cwe']} / {row['severity']}"
        )
        out.append(f"  file      {row['file']}:{row['line']}")
        out.append(f"  rule      {row['rule_id']}")
        out.append(
            f"  Laya      route={row['laya_route']} "
            f"conf={row['laya_confidence']} "
            f"needs_human={row['needs_human_review']} "
            f"suff={row['evidence_sufficiency']}"
        )
        if row["laya_probs"]:
            top = max(row["laya_probs"].items(), key=lambda kv: kv[1])
            out.append(f"            top choice={top[0]} p={top[1]}")
        out.append(f"  message   {row['message']}")
        if row["source"]:
            out.append("  ---")
            for line in row["source"].splitlines():
                out.append(f"  {line}")
        else:
            out.append("  (source not reachable from checkout)")
        out.append(f"  -> LABEL expected_route: {row['expected_route']}")
        out.append("")

    if limit is not None and len(rows) > limit:
        out.append(f"... {len(rows) - limit} more in the JSON sheet")
    return "\n".join(out)
