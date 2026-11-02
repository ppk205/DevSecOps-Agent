"""Hooks only append to the queue, and never take over a foreign hook."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vulnscan.cli.main import app
from vulnscan.harness.hooks import (
    HOOK_NAMES,
    MARKER,
    HookError,
    current_python,
    hook_body,
    install,
    status,
    uninstall,
)
from vulnscan.harness.pending import read_pending, store_path

GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    (path / "A.java").write_text("class A {}\n", encoding="utf-8")
    subprocess.run(GIT + ["add", "-A"], cwd=path, check=True)
    subprocess.run(GIT + ["commit", "-qm", "first"], cwd=path, check=True)
    return path


def test_install_writes_both_hooks_executable(repo: Path) -> None:
    written = install(repo, Path(sys.executable))
    assert written == list(HOOK_NAMES)
    for name in HOOK_NAMES:
        path = repo / ".git" / "hooks" / name
        text = path.read_text(encoding="utf-8")
        assert MARKER in text and "\r" not in text
        assert text.endswith("exit 0\n")
        if os.name != "nt":
            assert os.access(path, os.X_OK)


def test_install_refuses_foreign_hook(repo: Path) -> None:
    hook = repo / ".git" / "hooks" / "post-commit"
    hook.write_text("#!/bin/sh\necho husky\n", encoding="utf-8")
    with pytest.raises(HookError) as excinfo:
        install(repo, Path(sys.executable))
    assert "Add this line to it" in str(excinfo.value)
    assert "record --hook post-commit" in str(excinfo.value)
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\necho husky\n"


def test_cli_install_exits_one_on_foreign_hook(repo: Path) -> None:
    (repo / ".git" / "hooks" / "post-merge").write_text("#!/bin/sh\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["hooks", "install", "--repo", str(repo)])
    assert result.exit_code == 1
    assert "Add this line to it" in result.output


def test_uninstall_removes_only_marked(repo: Path) -> None:
    install(repo, Path(sys.executable))
    (repo / ".git" / "hooks" / "pre-push").write_text("#!/bin/sh\n", encoding="utf-8")
    assert uninstall(repo) == list(HOOK_NAMES)
    assert status(repo) == {"post-commit": "absent", "post-merge": "absent"}
    assert (repo / ".git" / "hooks" / "pre-push").exists()


def test_status_reports_foreign(repo: Path) -> None:
    (repo / ".git" / "hooks" / "post-commit").write_text("#!/bin/sh\n", encoding="utf-8")
    assert status(repo) == {"post-commit": "foreign", "post-merge": "absent"}


def test_hook_with_missing_python_exits_zero(repo: Path) -> None:
    install(repo, Path("/nonexistent/python-devsec"))
    (repo / "B.java").write_text("class B {}\n", encoding="utf-8")
    subprocess.run(GIT + ["add", "-A"], cwd=repo, check=True)
    result = subprocess.run(
        GIT + ["commit", "-qm", "second"], cwd=repo, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert "could not queue review" in result.stderr
    assert result.stderr.count("\n") == 1


def test_commit_queues_review(repo: Path, tmp_path: Path) -> None:
    install(repo, current_python())
    (repo / "B.java").write_text("class B {}\n", encoding="utf-8")
    subprocess.run(GIT + ["add", "-A"], cwd=repo, check=True)
    subprocess.run(GIT + ["commit", "-qm", "second"], cwd=repo, check=True)
    store = store_path(tmp_path / "harness", repo)
    reviews = read_pending(repo, store)
    assert [review.source for review in reviews] == ["post-commit"]
    assert reviews[0].files == ["B.java"]


def test_hook_body_is_pinned() -> None:
    assert hook_body("post-commit", Path("/usr/bin/python3")).startswith(
        "#!/bin/sh\n# devsec-hook v1\n"
    )


def test_worktree_hooks_queue_review(repo: Path, tmp_path: Path) -> None:
    worktree = tmp_path / "linked"
    subprocess.run(GIT + ["worktree", "add", "-qb", "linked", str(worktree)], cwd=repo, check=True)
    assert (worktree / ".git").is_file()
    assert install(worktree, current_python()) == list(HOOK_NAMES)
    assert status(worktree) == {name: "installed" for name in HOOK_NAMES}
    (worktree / "B.java").write_text("class B {}\n")
    subprocess.run(GIT + ["add", "B.java"], cwd=worktree, check=True)
    subprocess.run(GIT + ["commit", "-qm", "linked"], cwd=worktree, check=True)
    reviews = read_pending(worktree, tmp_path / "pending.jsonl")
    assert len(reviews) == 1 and reviews[0].files == ["B.java"]
    assert uninstall(worktree) == list(HOOK_NAMES)


def test_symlink_hook_is_foreign_and_not_followed(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-hook"
    outside.write_text(hook_body("post-commit", current_python()))
    original = outside.read_text()
    try:
        os.symlink(outside, repo / ".git/hooks/post-commit")
    except OSError:
        pytest.skip("symlinks not permitted")
    assert status(repo)["post-commit"] == "foreign"
    with pytest.raises(HookError):
        install(repo, current_python())
    assert uninstall(repo) == []
    assert outside.read_text() == original


def test_status_does_not_create_hooks_directory(repo: Path) -> None:
    import shutil

    hooks = repo / ".git/hooks"
    shutil.rmtree(hooks)
    assert status(repo) == {name: "absent" for name in HOOK_NAMES}
    assert not hooks.exists()


def test_hook_interpreter_path_is_absolute_and_shell_literal(tmp_path: Path) -> None:
    path = tmp_path / 'python$HOME`id`"fake'
    body = hook_body("post-commit", path)
    assert 'python\\$HOME\\`id\\`\\"fake' in body
    assert Path("python").absolute().as_posix() in hook_body("post-commit", Path("python"))


@pytest.mark.parametrize("command", ["install", "uninstall", "status"])
@pytest.mark.parametrize("configured", ["custom-hooks", ""])
def test_custom_hooks_path_is_refused_without_touching_hooks(
    repo: Path, command: str, configured: str
) -> None:
    install(repo, current_python())
    original = {name: (repo / ".git/hooks" / name).read_bytes() for name in HOOK_NAMES}
    custom = repo / "custom-hooks"
    custom.mkdir()
    foreign = custom / "post-commit"
    foreign.write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
    subprocess.run(GIT + ["config", "core.hooksPath", configured], cwd=repo, check=True)
    with pytest.raises(HookError, match="core.hooksPath"):
        if command == "install":
            install(repo, current_python())
        elif command == "uninstall":
            uninstall(repo)
        else:
            status(repo)
    assert original == {name: (repo / ".git/hooks" / name).read_bytes() for name in HOOK_NAMES}
    assert foreign.read_text() == "#!/bin/sh\necho custom\n"


def test_global_hooks_path_is_refused(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "synthetic.gitconfig"
    config.write_text("[core]\n\thooksPath = custom-hooks\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    with pytest.raises(HookError, match="core.hooksPath"):
        install(repo, current_python())
    assert not (repo / ".git/hooks/post-commit").exists()


def test_worktree_custom_hooks_path_is_refused(repo: Path, tmp_path: Path) -> None:
    worktree = tmp_path / "linked"
    subprocess.run(GIT + ["worktree", "add", "-qb", "linked", str(worktree)], cwd=repo, check=True)
    subprocess.run(GIT + ["config", "core.hooksPath", "custom-hooks"], cwd=repo, check=True)
    with pytest.raises(HookError, match="core.hooksPath"):
        install(worktree, current_python())
    assert not (repo / ".git/hooks/post-commit").exists()


def test_hooks_config_query_failure_refuses_install(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = subprocess.run

    def fail_config(args, **kwargs):
        if "config" in args:
            return subprocess.CompletedProcess(args, 2, stdout=b"", stderr=b"config error")
        return run(args, **kwargs)

    monkeypatch.setattr("vulnscan.harness.pending.subprocess.run", fail_config)
    with pytest.raises(HookError, match="config"):
        install(repo, current_python())
    assert not (repo / ".git/hooks/post-commit").exists()
