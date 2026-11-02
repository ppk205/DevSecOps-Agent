"""Fix worktrees: apply on a branch, leave the target untouched, re-scan."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.harness.conftest import DIFF
from vulnscan.harness.fixes import FixError, apply_fix, rescan_fix
from vulnscan.harness.workspace import FixProposal, Workspace

GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]


def heads(ws: Workspace) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ws.target, capture_output=True, text=True, check=False
    ).stdout


def test_apply_on_branch_leaves_target_untouched(ws: Workspace, tmp_path: Path) -> None:
    before = (ws.target / "A.java").read_text(), heads(ws)
    fix = FixProposal("x1", "f1", DIFF)
    assert apply_fix(ws, fix, tmp_path / "wt") == "devsec/fix-f1"
    assert "SecureRandom" in (tmp_path / "wt/f1/A.java").read_text()
    assert ((ws.target / "A.java").read_text(), heads(ws)) == before and fix.status == "applied"
    assert rescan_fix(ws, fix, tmp_path / "wt") == "candidate gone"


def test_diff_outside_target_is_refused(ws: Workspace, tmp_path: Path) -> None:
    with pytest.raises(FixError):
        apply_fix(
            ws, FixProposal("x2", "f1", DIFF.replace("A.java", "../evil.java")), tmp_path / "wt"
        )


def test_diff_that_does_not_apply_leaves_no_branch(ws: Workspace, tmp_path: Path) -> None:
    with pytest.raises(FixError):
        apply_fix(
            ws,
            FixProposal("x3", "f1", DIFF.replace("new Random()", "new Other()", 1)),
            tmp_path / "wt",
        )
    branches = subprocess.run(
        ["git", "branch", "--list", "devsec/*"],
        cwd=ws.target,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    assert branches.strip() == ""


def test_existing_branch_is_refused(ws: Workspace, tmp_path: Path) -> None:
    subprocess.run(["git", "branch", "devsec/fix-f1"], cwd=ws.target, check=True)
    with pytest.raises(FixError):
        apply_fix(ws, FixProposal("x4", "f1", DIFF), tmp_path / "wt")
