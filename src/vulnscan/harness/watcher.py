"""Watch a folder without git and queue one review after changes settle.

An editor that saves thirty files over eight seconds must produce one review,
not thirty, so a change only queues after ``quiet`` seconds with no further
change. The watcher never writes inside the target: its queue and marks live
under the harness store.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from vulnscan.harness.pending import PendingReview, record_watch
from vulnscan.harness.workspace import Workspace

IGNORED_DIRS = frozenset({".devsec", ".git", "target", "build", "out", "node_modules"})


class Watcher:
    """Polling watcher; the host calls :meth:`tick` on a daemon thread."""

    def __init__(
        self,
        ws: Workspace,
        store: Path,
        clock: Callable[[], float] = time.monotonic,
        interval: float = 5.0,
        quiet: float = 10.0,
    ) -> None:
        self.ws = ws
        self.store = Path(store)
        self.clock = clock
        self.interval = interval
        self.quiet = quiet
        self._snapshot: dict[str, tuple[int, int]] | None = None
        self._pending: set[str] = set()
        self._last_change: float | None = None

    def _scan(self) -> dict[str, tuple[int, int]]:
        root = self.ws.target.resolve()
        found: dict[str, tuple[int, int]] = {}
        for path in self.ws.files():
            try:
                relative = path.resolve().relative_to(root)
            except ValueError:
                continue
            if any(part in IGNORED_DIRS for part in relative.parts):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            found[relative.as_posix()] = (stat.st_mtime_ns, stat.st_size)
        return found

    def tick(self) -> PendingReview | None:
        """One poll. Returns a review only when changes have gone quiet."""
        current = self._scan()
        now = self.clock()
        if self._snapshot is None:
            self._snapshot = current
            return None

        changed = {name for name, stamp in current.items() if self._snapshot.get(name) != stamp}
        changed.update(name for name in self._snapshot if name not in current)
        self._snapshot = current
        if changed:
            self._pending.update(changed)
            self._last_change = now
            return None

        if (
            self._pending
            and self._last_change is not None
            and now - self._last_change >= self.quiet
        ):
            files = sorted(self._pending)
            self._pending.clear()
            self._last_change = None
            return record_watch(self.store, files)
        return None
