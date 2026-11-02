"""The target checkout a session reads from, and the objects it records.

Every path a tool touches goes through :meth:`Workspace.resolve`, which rejects
absolute paths, drive letters, ``..`` and symlinks that leave the target.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

__all__ = [
    "Candidate",
    "FixProposal",
    "Hop",
    "PathEscape",
    "ProposedFinding",
    "Workspace",
]


class PathEscape(ValueError):
    """Raised when a tool asks for a path outside the target checkout."""


@dataclass
class Candidate:
    """One place in the target that may be a vulnerability."""

    id: str
    cwe: str
    kind: str
    file: str
    line: int
    snippet: str
    route: str | None = None
    has_source: bool = False
    has_auth_check: bool = False
    laya_route: str | None = None
    laya_confidence: float | None = None
    selected: bool = False


@dataclass
class Hop:
    """One step on a source-to-sink path."""

    file: str
    line: int
    code: str
    note: str = ""


@dataclass
class ProposedFinding:
    """A finding the model proposed; only a human sets its status."""

    id: str
    candidate_id: str
    title: str
    cwe: str
    path: list[Hop]
    explanation: str
    cvss_vector: str
    cvss_score: float | None = None
    evidence_errors: list[str] = field(default_factory=list)
    status: str = "proposed"
    decided_by: str = ""
    reason: str = ""
    tokens: int = 0


@dataclass
class FixProposal:
    """A diff the model proposed for a confirmed finding."""

    id: str
    finding_id: str
    diff: str
    test_hint: str = ""
    status: str = "proposed"
    branch: str | None = None
    rescan: str | None = None


def _git(cwd: Path, args: list[str]) -> str | None:
    """Run one fixed git command; ``None`` when it fails or git is absent."""
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


@dataclass
class Workspace:
    """The target checkout plus everything the session has recorded so far."""

    target: Path
    commit: str
    dirty: bool = False
    plan: dict[str, Any] | None = None
    candidates: dict[str, Candidate] = field(default_factory=dict)
    findings: dict[str, ProposedFinding] = field(default_factory=dict)
    fixes: dict[str, FixProposal] = field(default_factory=dict)
    open_batch: set[str] = field(default_factory=set)
    batch_tokens: int = 0

    @classmethod
    def open(cls, target: Path) -> Workspace:
        """Open *target* and record its HEAD commit and dirty state."""
        root = Path(target).resolve()
        commit = "unversioned"
        dirty = False
        head = _git(root, ["rev-parse", "HEAD"])
        if head:
            commit = head
            status = _git(root, ["status", "--porcelain"])
            dirty = bool(status)
        return cls(target=root, commit=commit, dirty=dirty)

    def resolve(self, rel: str) -> Path:
        """Resolve *rel* inside the target or raise :class:`PathEscape`."""
        raw = Path(rel)
        windows = PureWindowsPath(rel)
        if raw.is_absolute() or windows.drive or rel.startswith(("/", "\\")):
            raise PathEscape(f"{rel}: absolute paths are not allowed")
        if ".." in windows.parts:
            raise PathEscape(f"{rel}: parent path components are not allowed")
        if self._excluded(raw):
            raise PathEscape(f"{rel}: credential path is excluded")
        root = self.target.resolve()
        candidate = (root / raw).resolve()
        if candidate != root and not candidate.is_relative_to(root):
            raise PathEscape(f"{rel}: path leaves the target checkout")
        if self._excluded(candidate.relative_to(root)):
            raise PathEscape(f"{rel}: credential path is excluded")
        return candidate

    @staticmethod
    def _excluded(path: Path) -> bool:
        return any(
            name == ".secrets"
            or name == ".env"
            or (name.startswith(".env.") and name != ".env.example")
            for name in (part.lower() for part in path.parts)
        )

    def files(self, globs: list[str] | None = None) -> list[Path]:
        """Enumerate readable target files, validating each path before access."""
        root = self.target.resolve()
        found: dict[str, Path] = {}
        for pattern in globs or ["**/*"]:
            # Validate the glob too: an explicit linked directory must not
            # allow globbing outside the checkout.
            try:
                self.resolve(pattern)
            except PathEscape:
                continue
            for path in root.glob(pattern):
                relative = path.relative_to(root).as_posix()
                if ".git" in path.relative_to(root).parts:
                    continue
                try:
                    resolved = self.resolve(relative)
                except (PathEscape, OSError, RuntimeError):
                    continue
                if resolved.is_file():
                    found[relative] = path
        return [found[key] for key in sorted(found)]

    def read(self, rel: str, start: int = 1, end: int | None = None, max_lines: int = 400) -> str:
        """Numbered lines of a target file, capped at *max_lines*."""
        path = self.resolve(rel)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        first = max(start, 1)
        stop = len(lines) if end is None else min(end, len(lines))
        window = lines[first - 1 : stop]
        truncated = len(window) > max_lines
        window = window[:max_lines]
        numbered = [f"{number}: {text}" for number, text in enumerate(window, start=first)]
        if truncated:
            numbered.append(f"… truncated at {max_lines} lines")
        return "\n".join(numbered)

    def grep(
        self, pattern: str, glob: str = "**/*", max_hits: int = 200
    ) -> list[tuple[str, int, str]]:
        """Regex hits as ``(posix relative path, 1-based line, stripped text)``."""
        regex = re.compile(pattern)
        root = self.target.resolve()
        hits: list[tuple[str, int, str]] = []
        for path in self.files([glob]):
            try:
                text = self.resolve(path.relative_to(root).as_posix()).read_text(
                    encoding="utf-8", errors="strict"
                )
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    hits.append((path.relative_to(root).as_posix(), number, line.strip()))
                    if len(hits) >= max_hits:
                        return hits
        return hits
