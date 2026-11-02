"""Fix worktrees: apply on a branch, leave the target untouched, re-scan."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tests.harness.conftest import DIFF
from vulnscan.harness.fixes import FixError, apply_fix, changed_lines, diff_hunks, rescan_fix
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


def test_diff_hunks_reports_old_ranges() -> None:
    diff = (
        "--- a/A.java\n+++ b/A.java\n@@ -10,3 +10,4 @@\n-a\n+b\n+c\n d\n e\n"
        "--- a/B.java\n+++ b/B.java\n@@ -40 +40 @@\n-c\n+d\n"
    )
    assert diff_hunks(diff) == [("A.java", 10, 12), ("B.java", 40, 40)]


def test_changed_lines_counts_content_only() -> None:
    diff = "--- a/A.java\n+++ b/A.java\n@@ -1,2 +1,2 @@\n-old\n+new\n context\n"
    assert changed_lines(diff) == 2


def test_unversioned_apply_exports_patch_only(tmp_path: Path) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    (target / "A.java").write_text(
        "class A { int r(){ return new Random().nextInt(); } }\n", encoding="utf-8"
    )
    ws = Workspace(target, "unversioned")
    fix = FixProposal("x9", "f1", DIFF)
    path = apply_fix(ws, fix, tmp_path / "worktrees")
    patch = Path(path)
    assert patch == tmp_path / "patches" / "f1.patch"
    assert patch.read_text(encoding="utf-8") == DIFF
    assert fix.status == "exported"
    assert sorted(p.name for p in target.iterdir()) == ["A.java"]


@pytest.mark.parametrize("finding_id", ["../escape", "a/b", "C:escape", "..", "", "a\\b"])
def test_export_refuses_unsafe_finding_ids(tmp_path: Path, finding_id: str) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    with pytest.raises(FixError, match="finding id"):
        apply_fix(
            Workspace(target, "unversioned"), FixProposal("x", finding_id, DIFF), tmp_path / "wt"
        )


def test_export_never_overwrites_patch(tmp_path: Path) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    ws = Workspace(target, "unversioned")
    patch = Path(apply_fix(ws, FixProposal("x", "f1", DIFF), tmp_path / "wt"))
    with pytest.raises(FixError, match="exists"):
        apply_fix(
            ws, FixProposal("x", "f1", DIFF.replace("SecureRandom", "Other")), tmp_path / "wt"
        )
    assert patch.read_text() == DIFF


@pytest.mark.parametrize("versioned", [False, True])
def test_apply_refuses_output_inside_target(ws: Workspace, versioned: bool) -> None:
    if not versioned:
        ws.commit = "unversioned"
    with pytest.raises(FixError, match="target"):
        apply_fix(ws, FixProposal("x", "f1", DIFF), ws.target / ".devsec/worktrees")
    assert not (ws.target / ".devsec").exists()


def test_export_refuses_symlink_destination(tmp_path: Path) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, tmp_path / "patches", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted")
    with pytest.raises(FixError):
        apply_fix(Workspace(target, "unversioned"), FixProposal("x", "f1", DIFF), tmp_path / "wt")
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize(
    "diff",
    [
        "",
        "not a diff",
        "--- a/A.java\n+++ b/A.java\n",
        DIFF.replace("@@ -1 +1 @@", "@@ -1,20 +1 @@"),
        DIFF.replace("@@ -1 +1 @@", "@@ -x +1 @@"),
        DIFF + "--- a/B.java\n+++ b/B.java\n",
        "diff --git a/B.java b/B.java\n" + DIFF,
        DIFF + "unexpected trailer\n",
    ],
)
def test_malformed_diffs_are_refused_before_export(tmp_path: Path, diff: str) -> None:
    with pytest.raises(ValueError):
        diff_hunks(diff)
    with pytest.raises(FixError):
        apply_fix(
            Workspace(tmp_path / "target", "unversioned"),
            FixProposal("x", "f1", diff),
            tmp_path / "wt",
        )
    assert not (tmp_path / "patches").exists()


def test_diff_parser_counts_header_like_content() -> None:
    diff = "--- a/A.java\n+++ b/A.java\n@@ -1 +1 @@\n--- old\n+++ new\n"
    assert changed_lines(diff) == 2
    assert diff_hunks(diff) == [("A.java", 1, 1)]


def test_diff_parser_reports_deleted_file() -> None:
    diff = "--- a/A.java\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
    assert diff_hunks(diff) == [("A.java", 1, 1)]


def test_unversioned_rescan_unavailable(tmp_path: Path) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    (target / "A.java").write_text("class A {}\n", encoding="utf-8")
    ws = Workspace(target, "unversioned")
    fix = FixProposal("x9", "f1", DIFF)
    assert rescan_fix(ws, fix, tmp_path / "worktrees") == (
        "unavailable: target is not a git repository"
    )
