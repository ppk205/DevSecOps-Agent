"""Workspace tests: path confinement, numbered reads and capped grep."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from vulnscan.harness.workspace import PathEscape, Workspace


@pytest.fixture
def ws(tmp_path: Path) -> Workspace:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.java").write_text(
        "\n".join(f"line {i}" for i in range(1, 501)), encoding="utf-8"
    )
    return Workspace.open(tmp_path)


@pytest.mark.parametrize(
    "bad", ["../outside.txt", "src/../../x", "/etc/passwd", "C:\\Windows\\win.ini"]
)
def test_resolve_rejects_escapes(ws: Workspace, bad: str) -> None:
    with pytest.raises(PathEscape):
        ws.resolve(bad)


def test_resolve_rejects_symlink_out(
    ws: Workspace, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("out") / "secret.txt"
    outside.write_text("s")
    try:
        os.symlink(outside, ws.target / "link.txt")
    except OSError:
        pytest.skip("symlinks not permitted")
    with pytest.raises(PathEscape):
        ws.resolve("link.txt")


def test_read_numbers_lines_and_caps(ws: Workspace) -> None:
    out = ws.read("src/A.java", 10, None, max_lines=3)
    assert out.splitlines()[:3] == ["10: line 10", "11: line 11", "12: line 12"]
    assert "truncated at 3 lines" in out


def test_grep_returns_relative_hits_and_caps(ws: Workspace) -> None:
    hits = ws.grep(r"line 4\d*\b", "**/*.java", max_hits=5)
    assert hits[0] == ("src/A.java", 4, "line 4") and len(hits) == 5


def test_open_unversioned_and_git(tmp_path: Path) -> None:
    assert Workspace.open(tmp_path).commit == "unversioned"
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "f").write_text("x")
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "f"], cwd=tmp_path, check=True
    )
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "i"],
        cwd=tmp_path,
        check=True,
    )
    w = Workspace.open(tmp_path)
    assert len(w.commit) == 40 and w.dirty is False
