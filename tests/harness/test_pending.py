"""The queue records what changed, never a credential filename."""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path

import pytest

from vulnscan.harness.pending import (
    PendingReview,
    mark,
    read_pending,
    record_hook,
    record_watch,
    store_path,
)

GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]


def commit(repo: Path, message: str) -> None:
    subprocess.run(GIT + ["add", "-A"], cwd=repo, check=True)
    subprocess.run(GIT + ["commit", "-qm", message], cwd=repo, check=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    (path / "A.java").write_text("class A {}\n", encoding="utf-8")
    commit(path, "first")
    return path


def test_record_commit_lists_changed_files(repo: Path) -> None:
    (repo / "B.java").write_text("class B {}\n", encoding="utf-8")
    commit(repo, "second")
    review = record_hook(repo, "post-commit")
    assert review.files == ["B.java"]
    assert review.source == "post-commit"
    assert review.ref and len(review.ref) == 40


def test_record_merge_uses_orig_head(repo: Path) -> None:
    subprocess.run(GIT + ["checkout", "-qb", "side"], cwd=repo, check=True)
    (repo / "C.java").write_text("class C {}\n", encoding="utf-8")
    commit(repo, "side")
    subprocess.run(GIT + ["checkout", "-q", "master"], cwd=repo, check=True)
    (repo / "D.java").write_text("class D {}\n", encoding="utf-8")
    commit(repo, "main")
    subprocess.run(GIT + ["merge", "--no-ff", "-m", "merge side", "side"], cwd=repo, check=True)
    review = record_hook(repo, "post-merge")
    assert review.files == ["C.java"]
    assert review.source == "post-merge"


def test_read_skips_dismissed(repo: Path, tmp_path: Path) -> None:
    (repo / "B.java").write_text("class B {}\n", encoding="utf-8")
    commit(repo, "second")
    review = record_hook(repo, "post-commit")
    store = store_path(tmp_path / "harness", repo)
    assert [item.id for item in read_pending(repo, store)] == [review.id]
    mark(store, review.id, "dismissed")
    assert read_pending(repo, store) == []


def test_watch_queue_dedupes_and_marks_started(tmp_path: Path) -> None:
    store = store_path(tmp_path / "harness", tmp_path / "target")
    review = record_watch(store, ["b.java", "a.java", "b.java"])
    assert review.files == ["a.java", "b.java"]
    assert review.source == "watch"
    mark(store, review.id, "started")
    assert read_pending(None, store) == []


def test_credential_files_never_listed(repo: Path) -> None:
    (repo / ".env").write_text("A=1\n", encoding="utf-8")
    (repo / "A.java").write_text("class A { int x; }\n", encoding="utf-8")
    commit(repo, "touch env")
    review = record_hook(repo, "post-commit")
    assert review.files == ["A.java"]


def test_unknown_hook_and_state_are_errors(repo: Path, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        record_hook(repo, "pre-push")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        mark(store_path(tmp_path, repo), "x", "later")  # type: ignore[arg-type]


def test_pending_review_is_frozen() -> None:
    review = PendingReview("id", "watch", None, ["a"], "2026-01-01T00:00:00+00:00")
    with pytest.raises(dataclasses.FrozenInstanceError):
        review.id = "other"  # type: ignore[misc]
