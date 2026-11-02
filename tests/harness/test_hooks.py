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
