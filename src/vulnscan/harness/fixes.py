"""Apply an approved fix to a separate git worktree branch, then re-scan it.

The harness never commits, pushes or merges. A fix lands on
``devsec/fix-<finding_id>`` inside ``.devsec/worktrees/<finding_id>`` and the
target working tree and branches are left exactly as they were.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .scanning import extract_candidates
from .workspace import FixProposal, PathEscape, Workspace

__all__ = ["FixError", "apply_fix", "rescan_fix"]

_DIFF_PATH = re.compile(r"^(?:---|\+\+\+) [ab]/(.+?)\s*$")
_DEV_NULL = "/dev/null"


class FixError(RuntimeError):
    """Raised when a proposed fix cannot be applied safely."""


def _run(
    cwd: Path, args: list[str], input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            input=input_text,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FixError(f"git {args[0]} failed: {exc}") from exc


def _diff_paths(diff: str) -> list[str]:
    """Every target-relative path a diff reads or writes."""
    paths: list[str] = []
    for line in diff.splitlines():
        match = _DIFF_PATH.match(line)
        if match is None:
            continue
        path = match.group(1)
        if path != _DEV_NULL and path not in paths:
            paths.append(path)
    return paths


def _branch_exists(target: Path, branch: str) -> bool:
    return (
        _run(target, ["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"]).returncode == 0
    )


def _cleanup(target: Path, worktree: Path, branch: str) -> None:
    _run(target, ["worktree", "remove", "--force", str(worktree)])
    _run(target, ["branch", "-D", branch])


def apply_fix(ws: Workspace, fix: FixProposal, root: Path = Path(".devsec/worktrees")) -> str:
    """Apply *fix* on a new branch in a worktree; return the branch name."""
    if ws.commit == "unversioned":
        raise FixError("the target is not a git checkout, so a fix branch is impossible")
    paths = _diff_paths(fix.diff)
    if not paths:
        raise FixError("the diff does not touch any file")
    for path in paths:
        try:
            ws.resolve(path)
        except PathEscape as exc:
            raise FixError(str(exc)) from exc

    branch = f"devsec/fix-{fix.finding_id}"
    if _branch_exists(ws.target, branch):
        raise FixError(f"branch {branch} already exists; delete it or use another finding id")

    worktree = (Path(root) / fix.finding_id).resolve()
    if worktree.exists():
        raise FixError(f"worktree path already exists: {worktree}")
    worktree.parent.mkdir(parents=True, exist_ok=True)

    added = _run(ws.target, ["worktree", "add", "-b", branch, str(worktree), ws.commit])
    if added.returncode != 0:
        raise FixError(f"could not create {branch}: {added.stderr.strip()}")

    check = _run(worktree, ["apply", "--check", "-"], input_text=fix.diff)
    if check.returncode != 0:
        _cleanup(ws.target, worktree, branch)
        raise FixError(f"the diff does not apply: {check.stderr.strip()}")

    applied = _run(worktree, ["apply", "-"], input_text=fix.diff)
    if applied.returncode != 0:
        _cleanup(ws.target, worktree, branch)
        raise FixError(f"the diff could not be applied: {applied.stderr.strip()}")

    fix.status = "applied"
    fix.branch = branch
    return branch


def rescan_fix(ws: Workspace, fix: FixProposal, root: Path = Path(".devsec/worktrees")) -> str:
    """Re-extract candidates on the fixed files; report if the candidate is gone."""
    worktree = (Path(root) / fix.finding_id).resolve()
    if not worktree.is_dir():
        raise FixError(f"no worktree at {worktree}; apply the fix first")
    paths = _diff_paths(fix.diff)
    finding = ws.findings.get(fix.finding_id)
    candidate = ws.candidates.get(finding.candidate_id) if finding is not None else None

    result = "still present"
    if candidate is not None and paths:
        paths = list(dict.fromkeys([*paths, candidate.file]))
        scan = Workspace(target=worktree, commit=ws.commit)
        remaining = extract_candidates(scan, paths=paths)
        if not any(item.kind == candidate.kind and item.file in paths for item in remaining):
            result = "candidate gone"
    fix.rescan = result
    return result
