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
from pathlib import Path, PureWindowsPath
from threading import RLock
from typing import Literal
from uuid import uuid4

from vulnscan.harness.workspace import PathEscape, Workspace
from vulnscan.providers.credentials import redact_json

HOOKS = ("post-commit", "post-merge")
_STATES = ("started", "dismissed")
_GIT = ("git",)
_LOCK = RLock()


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
    """Run a fixed git command, preserving NUL-delimited filename output."""
    try:
        result = subprocess.run(
            [*_GIT, *args], cwd=repo, capture_output=True, check=False, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"git {args[0]} unavailable") from exc
    if result.returncode == 1 and args == ("config", "-z", "--get", "core.hooksPath"):
        return ""
    if result.returncode != 0:
        raise ValueError(f"git {args[0]} failed")
    output = result.stdout.decode("utf-8", errors="surrogateescape")
    return output if "-z" in args else output.rstrip("\r\n")


def _visible(paths: list[str], ws: Workspace | None = None) -> list[str]:
    """Drop credential files: their names never enter the queue."""
    visible: set[str] = set()
    for path in paths:
        raw = PureWindowsPath(path)
        if not path or raw.drive or raw.root or ".." in raw.parts or "\x00" in path:
            continue
        normalized = Path(path).as_posix()
        if Workspace._excluded(Path(*raw.parts)) or ".git" in raw.parts:
            continue
        if ws is not None:
            try:
                ws.resolve(normalized)
            except (PathEscape, OSError, RuntimeError):
                continue
        visible.add(normalized)
    return sorted(visible)


def plain_path(path: Path) -> Path:
    """Refuse credential paths and linked queue/hook storage before opening it."""
    path = path.absolute()
    if Workspace._excluded(path):
        raise ValueError("credential storage path is excluded")
    for part in (path, *path.parents):
        if part.is_symlink() or part.resolve() != part:
            raise ValueError("queue or hook storage must not use symlinks or path aliases")
    return path


def git_directory(repo: Path, *, common: bool = False) -> Path:
    """Git resolves a real worktree's .git file; hooks use its common directory."""
    marker = plain_path(repo / ".git")
    if not marker.exists():
        raise ValueError(f"{repo} is not a git checkout")
    args = (
        ("rev-parse", "--path-format=absolute", "--git-common-dir")
        if common
        else ("rev-parse", "--absolute-git-dir")
    )
    directory = _git(repo, *args)
    if not directory:
        raise ValueError(f"cannot locate git directory for {repo}")
    return plain_path(Path(directory))


def hooks_directory(repo: Path) -> Path:
    """Return the default common hooks directory; refuse configured overrides."""
    directory = git_directory(repo, common=True)
    if _git(repo, "config", "-z", "--get", "core.hooksPath"):
        raise ValueError("core.hooksPath is configured; custom hook directories are not supported")
    return plain_path(directory / "hooks")


def _queue_path(repo: Path) -> Path:
    return git_directory(repo) / "devsec" / "pending.jsonl"


def store_path(store: Path, target: Path) -> Path:
    """The watch queue for one target, keyed by its resolved path."""
    digest = hashlib.sha1(str(target.resolve()).encode()).hexdigest()[:12]
    return store / ".devsec" / "pending" / f"{digest}.jsonl"


def _append(path: Path, review: PendingReview) -> PendingReview:
    path = plain_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, path.open("a", encoding="utf-8") as handle:
        handle.write(redact_json(asdict(review)) + "\n")
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
        files = _git(
            repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-z", "-r", "HEAD"
        )
    else:
        files = _git(repo, "diff", "--name-only", "-z", "ORIG_HEAD", "HEAD")
    changed = _visible(files.split("\0"), Workspace(repo, "unversioned"))
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
        id=uuid4().hex,
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
        payload = json.loads(plain_path(_state_path(store)).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in payload.items()
        if isinstance(value, str) and value in _STATES
    }


def mark(store: Path, review_id: str, state: Literal["started", "dismissed"]) -> None:
    """Record that a review started or was dismissed; the queue stays intact."""
    if state not in _STATES:
        raise ValueError(f"unknown state: {state}")
    if not isinstance(review_id, str) or not review_id:
        raise ValueError("review id must be a non-empty string")
    path = plain_path(_state_path(store))
    with _LOCK:
        states = _states(store)
        states[review_id] = state
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8") as handle:
                handle.write(redact_json(states))
            plain_path(path)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def _read(path: Path, ws: Workspace | None = None) -> list[PendingReview]:
    try:
        lines = plain_path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError):
        return []
    reviews: list[PendingReview] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                continue
            if any(
                not isinstance(payload.get(key), str) or not payload[key]
                for key in ("id", "source", "at")
            ):
                continue
            if payload["source"] not in (*HOOKS, "watch"):
                continue
            if payload.get("ref") is not None and not isinstance(payload["ref"], str):
                continue
            files = payload.get("files")
            if not isinstance(files, list) or any(not isinstance(item, str) for item in files):
                continue
            reviews.append(
                PendingReview(
                    id=payload["id"],
                    source=payload["source"],
                    ref=payload.get("ref"),
                    files=_visible(files, ws),
                    at=payload["at"],
                )
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return reviews


def read_pending(repo: Path | None, store: Path) -> list[PendingReview]:
    """Every queued review that has not been started or dismissed."""
    queues: list[Path] = [store]
    if repo is not None:
        try:
            queues.insert(0, _queue_path(Path(repo)))
        except (OSError, ValueError):
            pass
    dismissed: set[str] = set()
    for queue in queues:
        states = _states(queue)
        dismissed.update(key for key, value in states.items() if value in _STATES)
    seen: dict[str, PendingReview] = {}
    for queue in queues:
        for review in _read(queue, Workspace(repo, "unversioned") if repo is not None else None):
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
    except Exception:  # noqa: BLE001 - a hook must never fail a commit
        print("devsec: could not queue review", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - hook entry point
    raise SystemExit(main())
