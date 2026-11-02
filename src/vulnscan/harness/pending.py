"""A queue of reviews to run later, fed by git hooks and the folder watcher.

Hooks must never block a commit: every failure path here exits 0 and prints at
most one line to stderr. The queue is append-only JSONL; ``mark`` writes a
separate state file so a queued review is never edited or deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from vulnscan.harness.workspace import Workspace

HOOKS = ("post-commit", "post-merge")
_STATES = ("started", "dismissed")
_GIT = ("git",)


@dataclass(frozen=True)
class PendingReview:
    id: str
    source: str
    ref: str | None
    files: list[str]
    at: str


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _git(repo: Path, *args: str) -> str:
    """Run one fixed git command; empty output on any failure."""
    try:
        result = subprocess.run(
            [*_GIT, *args], cwd=repo, capture_output=True, text=True, check=False
        )
    except OSError:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _visible(paths: list[str]) -> list[str]:
    """Drop credential files: their names never enter the queue."""
    return [path for path in paths if path and not Workspace._excluded(Path(path))]


def _queue_path(repo: Path) -> Path:
    return repo / ".git" / "devsec" / "pending.jsonl"


def store_path(store: Path, target: Path) -> Path:
    """The watch queue for one target, keyed by its resolved path."""
    digest = hashlib.sha1(str(target.resolve()).encode()).hexdigest()[:12]
    return store / ".devsec" / "pending" / f"{digest}.jsonl"


def _append(path: Path, review: PendingReview) -> PendingReview:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(review)) + "\n")
    return review


def _review_id(source: str, ref: str | None, files: list[str]) -> str:
    seed = "|".join([source, ref or "", *sorted(files)])
    return hashlib.sha1(seed.encode()).hexdigest()[:16]


def record_hook(repo: Path, hook: Literal["post-commit", "post-merge"]) -> PendingReview:
    """Queue a review for the commit or merge git just made."""
    if hook not in HOOKS:
        raise ValueError(f"unknown hook: {hook}")
    repo = Path(repo)
    if hook == "post-commit":
        files = _git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD")
    else:
        files = _git(repo, "diff", "--name-only", "ORIG_HEAD", "HEAD")
    changed = _visible(files.splitlines())
    ref = _git(repo, "rev-parse", "HEAD") or None
    review = PendingReview(
        id=_review_id(hook, ref, changed),
        source=hook,
        ref=ref,
        files=changed,
        at=_now(),
    )
    return _append(_queue_path(repo), review)


def record_watch(store: Path, files: list[str]) -> PendingReview:
    """Queue a review for changed files in a target without git."""
    changed = _visible(sorted(set(files)))
    review = PendingReview(
        id=_review_id("watch", None, changed),
        source="watch",
        ref=None,
        files=changed,
        at=_now(),
    )
    return _append(store, review)


def _state_path(store: Path) -> Path:
    return store.with_suffix(".state.json")


def _states(store: Path) -> dict[str, str]:
    try:
        payload = json.loads(_state_path(store).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {
        str(key): str(value)
        for key, value in payload.items()
        if isinstance(payload, dict) and value in _STATES
    }


def mark(store: Path, review_id: str, state: Literal["started", "dismissed"]) -> None:
    """Record that a review started or was dismissed; the queue stays intact."""
    if state not in _STATES:
        raise ValueError(f"unknown state: {state}")
    states = _states(store)
    states[review_id] = state
    _state_path(store).parent.mkdir(parents=True, exist_ok=True)
    _state_path(store).write_text(json.dumps(states, indent=2, sort_keys=True), encoding="utf-8")


def _read(path: Path) -> list[PendingReview]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    reviews: list[PendingReview] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            reviews.append(
                PendingReview(
                    id=str(payload["id"]),
                    source=str(payload["source"]),
                    ref=payload.get("ref"),
                    files=[str(item) for item in payload.get("files", [])],
                    at=str(payload["at"]),
                )
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return reviews


def read_pending(repo: Path | None, store: Path) -> list[PendingReview]:
    """Every queued review that has not been started or dismissed."""
    queues: list[Path] = [store]
    if repo is not None:
        queues.insert(0, _queue_path(Path(repo)))
    dismissed: set[str] = set()
    for queue in queues:
        states = _states(queue)
        dismissed.update(key for key, value in states.items() if value in _STATES)
    seen: dict[str, PendingReview] = {}
    for queue in queues:
        for review in _read(queue):
            if review.id not in dismissed:
                seen.setdefault(review.id, review)
    return sorted(seen.values(), key=lambda review: (review.at, review.id))


def main(argv: list[str] | None = None) -> int:
    """``python -m vulnscan.harness.pending record --hook post-commit``."""
    parser = argparse.ArgumentParser(prog="vulnscan.harness.pending")
    sub = parser.add_subparsers(dest="command", required=True)
    record = sub.add_parser("record", help="queue a review for the commit just made")
    record.add_argument("--hook", choices=HOOKS, required=True)
    record.add_argument("--repo", default=".", help="repository root (default: cwd)")
    args = parser.parse_args(argv)
    try:
        record_hook(Path(args.repo), args.hook)
    except Exception as exc:  # noqa: BLE001 - a hook must never fail a commit
        print(f"devsec: could not queue review: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - hook entry point
    raise SystemExit(main())
