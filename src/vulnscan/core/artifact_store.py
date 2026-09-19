"""Content-addressed artifact store (sha256 -> path), grouped by run.

Artifacts are raw scanner outputs, source snapshots, and generated reports.
They must be identifiable by run *and* attempt: a retry must preserve the
prior attempt's artifacts rather than overwriting them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class StoredArtifact:
    """Pointer to a stored artifact."""
    run_id: int
    attempt: int
    checksum: str
    path: Path
    kind: str
    name: str


class ArtifactStore:
    """Filesystem-backed, content-addressed artifact store.

    Layout::

        <root>/run-<run_id>/attempt-<attempt>/<checksum>/<name>

    A different checksum cannot overwrite an existing artifact.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _dir_for(self, run_id: int, attempt: int) -> Path:
        return self.root / f"run-{run_id}" / f"attempt-{attempt}"

    def save_bytes(
        self,
        run_id: int,
        attempt: int,
        name: str,
        data: bytes,
        kind: str = "raw",
    ) -> StoredArtifact:
        """Store raw bytes; the checksum is computed, never accepted as input."""
        checksum = hashlib.sha256(data).hexdigest()
        d = self._dir_for(run_id, attempt) / checksum
        d.mkdir(parents=True, exist_ok=True)
        p = d / name
        if p.exists():
            # Same name but different content would be a content collision; refuse.
            if hashlib.sha256(p.read_bytes()).hexdigest() != checksum:
                raise FileExistsError(
                    f"artifact name collision with different content: {p}"
                )
        else:
            p.write_bytes(data)
        return StoredArtifact(run_id, attempt, checksum, p, kind, name)

    def save_json(self, run_id: int, attempt: int, name: str, obj: Any, kind: str = "json") -> StoredArtifact:
        """Serialize obj to JSON and store it (sorted keys for stability)."""
        data = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return self.save_bytes(run_id, attempt, name, data, kind=kind)

    def save_text(self, run_id: int, attempt: int, name: str, text: str, kind: str = "text") -> StoredArtifact:
        return self.save_bytes(run_id, attempt, name, text.encode("utf-8"), kind=kind)

    def retrieve(self, run_id: int, attempt: int, checksum: str, name: str) -> bytes:
        p = self._dir_for(run_id, attempt) / checksum / name
        if not p.exists():
            raise FileNotFoundError(f"no such artifact: {p}")
        data = p.read_bytes()
        if hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError(f"checksum mismatch on read: {p}")
        return data

    def list_by_run(self, run_id: int, attempt: int | None = None) -> list[StoredArtifact]:
        """List artifacts for a run; pass attempt to filter to one attempt."""
        out: list[StoredArtifact] = []
        run_dir = self.root / f"run-{run_id}"
        if not run_dir.exists():
            return out
        for att_dir in sorted(run_dir.iterdir(), key=lambda p: p.name):
            if not att_dir.is_dir():
                continue
            if attempt is not None:
                if att_dir.name != f"attempt-{attempt}":
                    continue
            for cs_dir in sorted(att_dir.iterdir()):
                if not cs_dir.is_dir():
                    continue
                for f in sorted(cs_dir.iterdir()):
                    out.append(
                        StoredArtifact(
                            run_id=run_id,
                            attempt=int(att_dir.name.removeprefix("attempt-")),
                            checksum=cs_dir.name,
                            path=f,
                            kind="raw",
                            name=f.name,
                        )
                    )
        return out
