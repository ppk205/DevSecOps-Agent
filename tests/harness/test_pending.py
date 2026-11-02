"""The queue records what changed, never a credential filename."""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from vulnscan.harness.pending import (
    PendingReview,
    _git,
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


def test_record_root_commit_lists_changed_files(repo: Path) -> None:
    assert record_hook(repo, "post-commit").files == ["A.java"]


@pytest.mark.parametrize("hook", ["post-commit", "post-merge"])
def test_hook_preserves_unicode_and_leading_space_names(repo: Path, hook: str) -> None:
    if hook == "post-merge":
        subprocess.run(GIT + ["checkout", "-qb", "side"], cwd=repo, check=True)
    files = [" leading space.java", "Đổi.java"]
    for name in files:
        (repo / name).write_text("class A {}\n", encoding="utf-8")
    commit(repo, "unusual filenames")
    if hook == "post-merge":
        subprocess.run(GIT + ["checkout", "-q", "master"], cwd=repo, check=True)
        subprocess.run(GIT + ["merge", "--ff-only", "side"], cwd=repo, check=True)
    review = record_hook(repo, hook)  # type: ignore[arg-type]
    assert review.files == files


def test_nul_git_output_preserves_filename_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = " leading\r\nline\tĐổi.java\0next.java\0".encode()
    monkeypatch.setattr(
        "vulnscan.harness.pending.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, stdout=raw, stderr=b""),
    )
    assert _git(Path("."), "diff", "--name-only", "-z", "ORIG_HEAD", "HEAD") == raw.decode()


def test_posix_filename_backslash_is_not_rewritten(monkeypatch: pytest.MonkeyPatch) -> None:
    from vulnscan.harness import pending

    monkeypatch.setattr(pending, "Path", PurePosixPath)
    assert pending._visible(["literal\\name.java", "dir\\.secrets\\alias.java"]) == [
        "literal\\name.java"
    ]


@pytest.mark.parametrize("hook", ["post-commit", "post-merge"])
def test_hook_splits_only_at_nul(repo: Path, monkeypatch: pytest.MonkeyPatch, hook: str) -> None:
    from vulnscan.harness.workspace import Workspace

    files = [" one\r\nline\tfile.java", "two.java"]
    monkeypatch.setattr(Workspace, "resolve", lambda self, rel: self.target / rel)
    monkeypatch.setattr(
        "vulnscan.harness.pending._git",
        lambda repo, *args: (
            "\0".join(files) + "\0"
            if args[0] in {"diff", "diff-tree"}
            else (str(repo / ".git") if "--absolute-git-dir" in args else "a" * 40)
        ),
    )
    assert record_hook(repo, hook).files == files  # type: ignore[arg-type]


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


def test_same_files_saved_again_get_new_review_id(tmp_path: Path) -> None:
    store = tmp_path / "pending.jsonl"
    first = record_watch(store, ["A.java"])
    mark(store, first.id, "dismissed")
    second = record_watch(store, ["A.java"])
    assert second.id != first.id
    assert read_pending(None, store) == [second]


@pytest.mark.parametrize("payload", [[], None, 1, "broken", {"x": []}])
def test_malformed_state_does_not_break_queue(tmp_path: Path, payload: object) -> None:
    store = tmp_path / "pending.jsonl"
    review = record_watch(store, ["A.java"])
    store.with_suffix(".state.json").write_text(json.dumps(payload))
    assert read_pending(None, store) == [review]
    mark(store, review.id, "started")
    assert read_pending(None, store) == []


def test_malformed_queue_records_are_ignored(tmp_path: Path) -> None:
    store = tmp_path / "pending.jsonl"
    review = record_watch(store, ["A.java"])
    valid = dataclasses.asdict(review)
    with store.open("a", encoding="utf-8") as handle:
        for payload in [
            None,
            [],
            3,
            "bad",
            {**valid, "id": []},
            {**valid, "files": "A.java"},
            {**valid, "ref": {}},
        ]:
            handle.write(json.dumps(payload) + "\n")
        handle.write('{"truncated":')
    assert read_pending(None, store) == [review]


def test_queue_filters_untrusted_paths_on_write_and_read(tmp_path: Path) -> None:
    store = tmp_path / "pending.jsonl"
    paths = [
        "A.java",
        "../escape.java",
        "C:\\private.java",
        "/abs.java",
        ".env",
        "x\\.secrets\\alias.java",
    ]
    review = record_watch(store, paths)
    assert review.files == ["A.java"]
    store.write_text(json.dumps({**dataclasses.asdict(review), "files": paths}) + "\n")
    assert read_pending(None, store)[0].files == ["A.java"]


def test_hook_filters_resolved_credential_alias(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    try:
        os.symlink(repo / ".secrets", repo / "Alias.java")
    except OSError:
        pytest.skip("symlinks not permitted")
    monkeypatch.setattr(
        "vulnscan.harness.pending._git",
        lambda repo, *args: (
            "Alias.java\0A.java\0"
            if args[0] == "diff-tree"
            else (str(repo / ".git") if "--absolute-git-dir" in args else "a" * 40)
        ),
    )
    assert record_hook(repo, "post-commit").files == ["A.java"]


@pytest.mark.parametrize("state_link", [False, True])
def test_queue_refuses_symlink_files(tmp_path: Path, state_link: bool) -> None:
    store = tmp_path / "pending.jsonl"
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    path = store.with_suffix(".state.json") if state_link else store
    try:
        os.symlink(outside, path)
    except OSError:
        pytest.skip("symlinks not permitted")
    with pytest.raises(ValueError):
        if state_link:
            mark(store, "x", "dismissed")
        else:
            record_watch(store, ["A.java"])
    assert outside.read_text() == "{}"
    assert read_pending(None, store) == []


def test_record_hook_in_worktree_uses_its_git_directory(repo: Path, tmp_path: Path) -> None:
    worktree = tmp_path / "linked"
    subprocess.run(GIT + ["worktree", "add", "-qb", "linked", str(worktree)], cwd=repo, check=True)
    (worktree / "B.java").write_text("class B {}\n")
    commit(worktree, "linked change")
    review = record_hook(worktree, "post-commit")
    assert review.files == ["B.java"]
    assert read_pending(worktree, tmp_path / "store.jsonl") == [review]
    assert read_pending(repo, tmp_path / "store.jsonl") == []
