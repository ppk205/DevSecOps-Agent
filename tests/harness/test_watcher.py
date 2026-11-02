"""One review per burst of edits, and nothing written inside the target."""

from __future__ import annotations

from pathlib import Path

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
