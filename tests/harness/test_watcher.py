"""One review per burst of edits, and nothing written inside the target."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnscan.harness.pending import read_pending, store_path
from vulnscan.harness.watcher import Watcher
from vulnscan.harness.workspace import Workspace


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def make(tmp_path: Path) -> tuple[Path, Watcher, Clock]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "A.java").write_text("class A {}\n", encoding="utf-8")
    store = store_path(tmp_path / "harness", target)
    clock = Clock()
    return target, Watcher(Workspace(target, "unversioned"), store, clock=clock), clock


def test_debounce_queues_once(tmp_path: Path) -> None:
    target, watcher, clock = make(tmp_path)
    watcher.tick()
    for index in range(30):
        (target / f"File{index}.java").write_text(f"class C{index} {{}}\n", encoding="utf-8")
        clock.now += 0.25
        assert watcher.tick() is None
    clock.now += 5
    assert watcher.tick() is None
    clock.now += 5
    review = watcher.tick()
    assert review is not None and len(review.files) == 30
    clock.now += 30
    assert watcher.tick() is None
    assert len(read_pending(None, watcher.store)) == 1


def test_no_change_no_review(tmp_path: Path) -> None:
    _target, watcher, clock = make(tmp_path)
    watcher.tick()
    clock.now += 100
    assert watcher.tick() is None


def test_ignored_dirs_do_not_trigger(tmp_path: Path) -> None:
    target, watcher, clock = make(tmp_path)
    watcher.tick()
    (target / "target").mkdir()
    (target / "target/Build.class").write_bytes(b"x")
    clock.now += 1
    assert watcher.tick() is None
    clock.now += 20
    assert watcher.tick() is None


def test_watcher_never_writes_in_target(tmp_path: Path) -> None:
    target, watcher, clock = make(tmp_path)
    watcher.tick()
    (target / "B.java").write_text("class B {}\n", encoding="utf-8")
    clock.now += 5
    watcher.tick()
    clock.now += 10
    assert watcher.tick() is not None
    assert sorted(p.name for p in target.iterdir()) == ["A.java", "B.java"]


def test_watcher_refuses_store_inside_target(tmp_path: Path) -> None:
    target, watcher, _ = make(tmp_path)
    with pytest.raises(ValueError, match="target"):
        Watcher(watcher.ws, target / ".devsec/pending.jsonl")


def test_queue_write_failure_keeps_pending_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vulnscan.harness.pending import record_watch

    target, watcher, clock = make(tmp_path)
    watcher.tick()
    (target / "B.java").write_text("class B {}\n")
    watcher.tick()
    clock.now += 10

    def broken(*args: object) -> None:
        raise OSError("queue unavailable")

    monkeypatch.setattr("vulnscan.harness.watcher.record_watch", broken)
    with pytest.raises(OSError):
        watcher.tick()
    monkeypatch.setattr("vulnscan.harness.watcher.record_watch", record_watch)
    review = watcher.tick()
    assert review is not None and review.files == ["B.java"]


def test_changed_file_replaced_by_credential_alias_is_not_queued(tmp_path: Path) -> None:
    import os

    target, watcher, clock = make(tmp_path)
    watcher.tick()
    (target / "A.java").write_text("class A { int x; }\n")
    watcher.tick()
    (target / "A.java").unlink()
    try:
        os.symlink(target / ".secrets", target / "A.java")
    except OSError:
        pytest.skip("symlinks not permitted")
    watcher.tick()
    clock.now += 10
    assert watcher.tick() is None
    assert read_pending(None, watcher.store) == []


def test_alias_into_ignored_directory_does_not_trigger(tmp_path: Path) -> None:
    import os

    target, watcher, clock = make(tmp_path)
    (target / "build").mkdir()
    built = target / "build/Generated.java"
    built.write_text("class Generated {}\n")
    try:
        os.symlink(built, target / "Alias.java")
    except OSError:
        pytest.skip("symlinks not permitted")
    watcher.tick()
    built.write_text("class Generated { int x; }\n")
    watcher.tick()
    clock.now += 10
    assert watcher.tick() is None
