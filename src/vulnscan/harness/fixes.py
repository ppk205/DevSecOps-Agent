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

__all__ = ["FixError", "apply_fix", "changed_lines", "diff_hunks", "rescan_fix"]

_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?")
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
    return list(dict.fromkeys(file for file, _, _ in diff_hunks(diff)))


def _branch_exists(target: Path, branch: str) -> bool:
    return (
        _run(target, ["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"]).returncode == 0
    )


def _cleanup(target: Path, worktree: Path, branch: str) -> None:
    _run(target, ["worktree", "remove", "--force", str(worktree)])
    _run(target, ["branch", "-D", branch])


def _parse_diff(diff: str) -> tuple[list[tuple[str, int, int]], int]:
    """Validate text hunks before trusting their paths, ranges or line counts.

    ponytail: only unified text patches; renames, mode changes, binary patches
    and quoted git paths are refused rather than partially parsed.
    """
    lines = diff.splitlines()
    hunks: list[tuple[str, int, int]] = []
    changed = 0
    index = 0
    seen: set[str] = set()
    while index < len(lines):
        git_header = None
        if lines[index].startswith("diff --git "):
            git_header = lines[index]
            index += 1
            if index < len(lines) and lines[index].startswith("index "):
                if not re.fullmatch(
                    r"index [0-9a-f]+\.\.[0-9a-f]+(?: 100(?:644|755))?", lines[index]
                ):
                    raise ValueError("malformed or unsupported diff index")
                index += 1
        if (
            index + 1 >= len(lines)
            or not lines[index].startswith("--- ")
            or not lines[index + 1].startswith("+++ ")
        ):
            raise ValueError("malformed diff: expected paired ---/+++ file headers")
        old, new = lines[index][4:], lines[index + 1][4:]
        if (old != _DEV_NULL and not old.startswith("a/")) or (
            new != _DEV_NULL and not new.startswith("b/")
        ):
            raise ValueError("malformed diff: expected a/ and b/ relative paths")
        file = old[2:] if old != _DEV_NULL else new[2:]
        if (
            not file
            or old == new == _DEV_NULL
            or (old != _DEV_NULL and new != _DEV_NULL and old[2:] != new[2:])
        ):
            raise ValueError("malformed diff: renamed or missing file path")
        if any(char in file for char in '\t\r\n\x00"') or file != file.strip():
            raise ValueError("unsupported diff path")
        if git_header is not None and git_header != f"diff --git a/{file} b/{file}":
            raise ValueError(f"malformed diff: conflicting paths for {file}")
        if file in seen:
            raise ValueError(f"malformed diff: duplicate file section for {file}")
        seen.add(file)
        index += 2
        file_hunks = len(hunks)
        previous_old_end = previous_new_end = -1
        while index < len(lines) and lines[index].startswith("@@"):
            match = _HUNK.fullmatch(lines[index])
            if match is None:
                raise ValueError(f"malformed diff hunk in {file}")
            start, count, new_start, new_count = (
                int(match[1]),
                int(match[2] or 1),
                int(match[3]),
                int(match[4] or 1),
            )
            if (count and not start) or (new_count and not new_start) or not (count or new_count):
                raise ValueError(f"malformed diff range in {file}:{start}")
            if start < previous_old_end or new_start < previous_new_end:
                raise ValueError(f"overlapping diff hunks in {file}:{start}")
            if (old == _DEV_NULL and count) or (new == _DEV_NULL and new_count):
                raise ValueError(f"malformed diff creation/deletion in {file}:{start}")
            previous_old_end, previous_new_end = start + count, new_start + new_count
            index += 1
            old_read = new_read = hunk_changes = 0
            while old_read < count or new_read < new_count:
                if index >= len(lines) or not lines[index] or lines[index][0] not in " +-":
                    raise ValueError(f"malformed diff body in {file}:{start}")
                prefix = lines[index][0]
                old_read += prefix in " -"
                new_read += prefix in " +"
                hunk_changes += prefix in "+-"
                index += 1
                if index < len(lines) and lines[index] == "\\ No newline at end of file":
                    index += 1
                if old_read > count or new_read > new_count:
                    raise ValueError(f"malformed diff line counts in {file}:{start}")
            if not hunk_changes:
                raise ValueError(f"diff hunk has no changes in {file}:{start}")
            changed += hunk_changes
            hunks.append((file, start, start + max(count, 1) - 1))
        if len(hunks) == file_hunks:
            raise ValueError(f"diff has no hunks for {file}")
    if not hunks:
        raise ValueError("the diff does not contain any text hunks")
    return hunks, changed


def diff_hunks(diff: str) -> list[tuple[str, int, int]]:
    """Old-file inclusive ranges; a pure insertion uses its old-file anchor.

    Malformed or unsupported diffs raise ``ValueError``.
    """
    return _parse_diff(diff)[0]


def changed_lines(diff: str) -> int:
    """Number of added plus removed content lines in *diff*."""
    return _parse_diff(diff)[1]


def _validate_id(finding_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", finding_id):
        raise FixError("invalid finding id: use letters, digits, underscores and hyphens")


def _destination(ws: Workspace, root: Path, name: str) -> Path:
    base = Path(root).absolute()
    path = base / name
    for part in (path, *path.parents):
        if part.is_symlink() or part.resolve() != part:
            raise FixError("fix output must not use symlinks or path aliases")
    try:
        out = Workspace(base, "unversioned").resolve(name)
    except PathEscape as exc:
        raise FixError(str(exc)) from exc
    if out.is_relative_to(ws.target.resolve()):
        raise FixError("fix output must be outside the target")
    return out


def _validate_diff(ws: Workspace, diff: str) -> list[str]:
    try:
        paths = _diff_paths(diff)
        for path in paths:
            if any(part.lower() in {".git", ".devsec"} for part in Path(path).parts):
                raise FixError("fix cannot touch repository or harness metadata")
            ws.resolve(path)
        return paths
    except (ValueError, OSError, RuntimeError) as exc:
        raise FixError(str(exc)) from exc


def _export_patch(ws: Workspace, fix: FixProposal, root: Path) -> str:
    """Write the proposal as a patch for a target that is not a git checkout.

    The patch lives beside the worktrees root, in ``patches/<finding_id>.patch``.
    Exclusive creation preserves previously exported proposals.
    """
    patch = _destination(ws, Path(root).parent / "patches", f"{fix.finding_id}.patch")
    patch.parent.mkdir(parents=True, exist_ok=True)
    try:
        with patch.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(fix.diff)
    except FileExistsError as exc:
        raise FixError(f"patch already exists: {patch}") from exc
    fix.status = "exported"
    fix.branch = ""
    return str(patch)


def apply_fix(ws: Workspace, fix: FixProposal, root: Path = Path(".devsec/worktrees")) -> str:
    """Apply *fix* on a new branch in a worktree; return the branch name."""
    _validate_id(fix.finding_id)
    _validate_diff(ws, fix.diff)
    if ws.commit == "unversioned":
        return _export_patch(ws, fix, root)

    branch = f"devsec/fix-{fix.finding_id}"
    if _branch_exists(ws.target, branch):
        raise FixError(f"branch {branch} already exists; delete it or use another finding id")

    worktree = _destination(ws, root, fix.finding_id)
    if worktree.exists():
        raise FixError(f"worktree path already exists: {worktree}")
    worktree.parent.mkdir(parents=True, exist_ok=True)

    added = _run(ws.target, ["worktree", "add", "-b", branch, str(worktree), ws.commit])
    if added.returncode != 0:
        raise FixError(f"could not create {branch}: {added.stderr.strip()}")

    try:
        _validate_diff(Workspace(worktree, ws.commit), fix.diff)
        check = _run(worktree, ["apply", "--check", "-"], input_text=fix.diff)
        if check.returncode != 0:
            raise FixError(f"the diff does not apply: {check.stderr.strip()}")
        applied = _run(worktree, ["apply", "-"], input_text=fix.diff)
        if applied.returncode != 0:
            raise FixError(f"the diff could not be applied: {applied.stderr.strip()}")
    except FixError:
        _cleanup(ws.target, worktree, branch)
        raise

    fix.status = "applied"
    fix.branch = branch
    return branch


def rescan_fix(ws: Workspace, fix: FixProposal, root: Path = Path(".devsec/worktrees")) -> str:
    """Re-extract candidates on the fixed files; report if the candidate is gone."""
    _validate_id(fix.finding_id)
    if ws.commit == "unversioned":
        fix.rescan = "unavailable: target is not a git repository"
        return fix.rescan
    worktree = _destination(ws, root, fix.finding_id)
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
