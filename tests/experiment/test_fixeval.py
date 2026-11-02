"""Synthetic fix fixtures, including real-git isolation; no measured fix claims."""

import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from vulnscan.experiment import fixeval
from vulnscan.experiment.groundtruth import GTItem, Row

GT = GTItem(
    "synthetic", "A.java", 1, 1, "CWE-330", "vuln", "injected", None, "test-a", "test-b", True
)
DIFF = "--- a/A.java\n+++ b/A.java\n@@ -1 +1 @@\n-new Random();\n+new SecureRandom();\n"


def fake_commands(monkeypatch, tmp_path, applies=True, compile_code=0):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "A.java").write_text("new Random();\n")
    calls = []

    def run(cwd, args, input_text=None):
        calls.append((cwd, args))
        assert cwd != repo
        code = 0
        if "clone" in args:
            Path(args[-1]).mkdir()
        elif "worktree" in args:
            shutil.copytree(repo, Path(args[-2]))
        elif args[:3] == ["git", "apply", "--check"]:
            code = 0 if applies else 1
        elif args[:2] == ["git", "apply"]:
            (cwd / "A.java").write_text("new SecureRandom();\n")
        elif args[0] == "mvn":
            assert args == ["mvn", "-q", "-o", "compile"]
            code = compile_code
        return subprocess.CompletedProcess(args, code, "", "synthetic failure" if code else "")

    monkeypatch.setattr(fixeval, "_run", run)
    return repo, calls


def row(file="A.java", line=1, cwe="CWE-330"):
    return Row("F1", 1, file, line, cwe, None, None, "baseline", "synthetic")


def test_missing_suggestion_counts_in_coverage():
    assert fixeval.coverage(["a", "b", "c"], {"a": DIFF, "b": ""}) == 1 / 3
    assert fixeval.coverage([], {}) is None


def test_scope_metric_flags_out_of_region_hunks(monkeypatch, tmp_path):
    repo, _ = fake_commands(monkeypatch, tmp_path)
    result = fixeval.evaluate_fix(
        repo, "a" * 40, DIFF.replace("@@ -1 +1 @@", "@@ -50 +50 @@"), GT, lambda p: []
    )
    assert not result.in_scope and result.lines_changed == 2
    assert result.human_verdict is None and result.human_reason is None


def test_non_applying_diff_scored_not_crashed(monkeypatch, tmp_path):
    repo, calls = fake_commands(monkeypatch, tmp_path, applies=False)
    result = fixeval.evaluate_fix(repo, "a" * 40, DIFF, GT, lambda p: [row()])
    assert result.applies is False and result.compiles is None
    assert result.vuln_removed_by_detector is None
    assert all(args[0] != "mvn" for _, args in calls)
    assert (repo / "A.java").read_text() == "new Random();\n"


def test_new_alerts_diffed(monkeypatch, tmp_path):
    repo, calls = fake_commands(monkeypatch, tmp_path)

    def detector(path):
        assert path != repo
        return (
            [row()]
            if "new Random" in (path / "A.java").read_text()
            else [row("B.java", 5, "CWE-79")]
        )

    score = fixeval.evaluate_fix(repo, "a" * 40, DIFF, GT, detector)
    assert score.applies and score.compiles and score.vuln_removed_by_detector
    assert score.new_alerts == 1 and score.in_scope
    assert any("--no-hardlinks" in args for _, args in calls)
    assert (repo / "A.java").read_text() == "new Random();\n"


def test_missing_before_detection_is_unknown(monkeypatch, tmp_path):
    repo, _ = fake_commands(monkeypatch, tmp_path)
    score = fixeval.evaluate_fix(repo, "a" * 40, DIFF, GT, lambda p: [])
    assert score.vuln_removed_by_detector is None


def test_moved_alert_is_not_removed_or_new(monkeypatch, tmp_path):
    repo, _ = fake_commands(monkeypatch, tmp_path)
    calls = []

    def detector(path):
        calls.append(path)
        if len(calls) == 1:
            return [row()]
        # The replacement stays at the same mapped site with an unstable id.
        return [replace(row(), source_id="new-line-based-id")]

    score = fixeval.evaluate_fix(repo, "a" * 40, DIFF, GT, detector)
    assert score.vuln_removed_by_detector is False and score.new_alerts == 0


def test_inserted_lines_move_alert_without_removal(monkeypatch, tmp_path):
    repo, _ = fake_commands(monkeypatch, tmp_path)
    original = fixeval._run

    def run(cwd, args, input_text=None):
        result = original(cwd, args, input_text)
        if args[:2] == ["git", "apply"] and "--check" not in args:
            (cwd / "A.java").write_text("// inserted\n" * 20 + "new Random();\n")
        return result

    monkeypatch.setattr(fixeval, "_run", run)

    def detector(path):
        return [
            row(line=n)
            for n, line in enumerate((path / "A.java").read_text().splitlines(), 1)
            if "new Random" in line
        ]

    score = fixeval.evaluate_fix(repo, "a" * 40, DIFF, GT, detector)
    assert score.vuln_removed_by_detector is False and score.new_alerts == 0


def test_patch_escape_never_applied(monkeypatch, tmp_path):
    repo, calls = fake_commands(monkeypatch, tmp_path)
    score = fixeval.evaluate_fix(
        repo, "a" * 40, DIFF.replace("A.java", "../outside.java"), GT, lambda p: []
    )
    assert not score.applies
    assert not any(args[:2] == ["git", "apply"] for _, args in calls)


def test_cli_writes_score_and_keeps_human_verdict_separate(monkeypatch, tmp_path):
    import json

    repo, _ = fake_commands(monkeypatch, tmp_path)
    gt = tmp_path / "gt.csv"
    gt.write_text(
        "id,file,line_start,line_end,cwe,kind,origin,cvss_vector,labeller_a,labeller_b,agreed\n"
        "synthetic,A.java,1,1,CWE-330,vuln,injected,,test-a,test-b,true\n"
    )
    patch = tmp_path / "fix.patch"
    patch.write_text(DIFF)
    out = tmp_path / "score.json"
    assert (
        fixeval.main(
            [
                "--repo",
                str(repo),
                "--commit",
                "a" * 40,
                "--gt",
                str(gt),
                "--finding",
                "synthetic",
                "--diff",
                str(patch),
                "--detector",
                "harness",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    assert json.loads(out.read_text())["human_verdict"] is None


@pytest.mark.parametrize(
    "diff",
    [
        "not a diff",
        "--- a/A.java\n+++ b/A.java\n@@ -1,9 +1 @@\n-x\n+y\n",
        "diff --git a/A.java b/B.java\nrename from A.java\nrename to B.java\n",
    ],
)
def test_unsupported_diff_is_recorded_before_commands(monkeypatch, tmp_path, diff):
    repo, calls = fake_commands(monkeypatch, tmp_path)
    result = fixeval.evaluate_fix(repo, "a" * 40, diff, GT, lambda p: [])
    assert not result.applies and result.errors and not calls


def test_scratch_directory_cannot_be_created_inside_target(monkeypatch, tmp_path):
    repo, calls = fake_commands(monkeypatch, tmp_path)
    monkeypatch.setattr(fixeval.tempfile, "gettempdir", lambda: str(repo))
    monkeypatch.setattr(
        fixeval.tempfile,
        "TemporaryDirectory",
        lambda **kwargs: pytest.fail("temporary directory created inside target"),
    )
    result = fixeval.evaluate_fix(repo, "a" * 40, DIFF, GT, lambda p: [])
    assert result.errors and not calls


def test_real_git_patch_isolated_from_source_and_scratch_cleaned(monkeypatch, tmp_path):
    """Real clone/worktree/apply; only compilation and detection are substitutes."""
    repo = tmp_path / "source"
    repo.mkdir()
    before_code = "class A { int next() { return new java.util.Random().nextInt(); } }\n"
    after_code = before_code.replace("java.util.Random", "java.security.SecureRandom")
    (repo / "A.java").write_text(before_code, encoding="utf-8", newline="\n")
    (repo / "notes.txt").write_text("committed synthetic note\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.delenv(name, raising=False)

    def git(*args):
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", *args],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout

    git("init", "--initial-branch=fixture")
    git("add", "A.java", "notes.txt")
    git(
        "-c",
        "user.name=Synthetic fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "Create synthetic fix fixture",
    )
    commit = git("rev-parse", "HEAD").strip()
    # A pinned clone must not copy or alter local dirty/untracked source files.
    (repo / "notes.txt").write_text("uncommitted synthetic note\n", encoding="utf-8")
    (repo / "untracked.txt").write_text("synthetic local file\n", encoding="utf-8")
    source_files = {path.name: path.read_bytes() for path in repo.iterdir() if path.is_file()}
    source_status = git("status", "--porcelain", "--untracked-files=all")
    source_refs = git("for-each-ref", "--format=%(refname) %(objectname)")
    source_worktrees = git("worktree", "list", "--porcelain")
    patch = f"--- a/A.java\n+++ b/A.java\n@@ -1 +1 @@\n-{before_code}+{after_code}"
    real_run = fixeval._run
    calls = []
    compilations = []

    def run(cwd, args, input_text=None):
        calls.append((cwd, args))
        assert not cwd.resolve().is_relative_to(repo.resolve())
        if args[0] == "mvn":
            assert args == ["mvn", "-q", "-o", "compile"]
            compilations.append(cwd)
            assert (cwd / "A.java").read_text(encoding="utf-8") == after_code
            return subprocess.CompletedProcess(args, 0, "synthetic compile substitute", "")
        assert args[0] == "git"
        return real_run(cwd, args, input_text)

    monkeypatch.setattr(fixeval, "_run", run)
    detected = []

    def detector(tree):
        code = (tree / "A.java").read_text(encoding="utf-8")
        detected.append((tree, code))
        assert (tree / "notes.txt").read_text(encoding="utf-8") == "committed synthetic note\n"
        assert not (tree / "untracked.txt").exists()
        gitdir = Path((tree / ".git").read_text(encoding="utf-8").strip().removeprefix("gitdir: "))
        assert gitdir.resolve().is_relative_to((tree.parent / "clone" / ".git").resolve())
        return [row()] if code == before_code else []

    score = fixeval.evaluate_fix(repo, commit, patch, GT, detector)
    assert score.errors == []
    assert score.applies and score.compiles and score.vuln_removed_by_detector
    assert score.new_alerts == 0 and score.in_scope
    assert (score.files_changed, score.lines_changed) == (1, 2)
    assert score.before_alerts == [row()] and score.after_alerts == []
    assert [code for _, code in detected] == [before_code, after_code]
    tree = detected[0][0]
    assert detected[1][0] == tree and compilations == [tree]
    assert any("clone" in args and "--no-hardlinks" in args for _, args in calls)
    assert any("worktree" in args and "--detach" in args for _, args in calls)
    assert any(args == ["git", "apply", "--check", "-"] for _, args in calls)
    assert any(args == ["git", "apply", "-"] for _, args in calls)
    assert git("rev-parse", "HEAD").strip() == commit
    assert {
        path.name: path.read_bytes() for path in repo.iterdir() if path.is_file()
    } == source_files
    assert git("status", "--porcelain", "--untracked-files=all") == source_status
    assert git("for-each-ref", "--format=%(refname) %(objectname)") == source_refs
    assert git("worktree", "list", "--porcelain") == source_worktrees
    assert not (repo / ".git" / "worktrees").exists()
    assert not tree.exists() and not (tree.parent / "clone").exists()
    assert not tree.parent.exists()
