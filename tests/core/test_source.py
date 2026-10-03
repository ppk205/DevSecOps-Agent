"""TDD: any repo can be scanned — local path, GitHub URL, or owner/repo slug."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulnscan.core.source import (
    LocalSource,
    RemoteSource,
    is_remote,
    resolve_source,
    slug_from_url,
)


class _Result:
    def __init__(self, succeeded: bool, stdout: str = "", stderr: str = "") -> None:
        self.succeeded = succeeded
        self.stdout = stdout
        self.stderr = stderr


class FakeCommand:
    """Records git invocations and fabricates a checkout on disk."""

    def __init__(self, commit: str = "a" * 40) -> None:
        self.calls: list[list[str]] = []
        self.commit = commit

    def __call__(self, argv, *, cwd=None, timeout=None, env=None, input_text=None):
        self.calls.append(list(argv))
        if argv[:2] == ["git", "clone"]:
            (Path(argv[-1]) / ".git").mkdir(parents=True, exist_ok=True)
        if argv[:2] == ["git", "init"]:
            (Path(str(cwd)) / ".git").mkdir(parents=True, exist_ok=True)
        if argv[:3] == ["git", "rev-parse", "HEAD"]:
            return _Result(True, self.commit + "\n")
        return _Result(True, "")

    def cloned(self) -> bool:
        return any(c[:2] == ["git", "clone"] for c in self.calls)


def make_git_repo(path: Path, filename: str = "A.java") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / filename).write_text("class A {}", encoding="utf-8")
    for args in (
        ["init"],
        ["add", "."],
        ["-c", "user.name=T", "-c", "user.email=t@e.invalid", "commit", "-m", "fixture"],
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)
    return path


def test_local_path_is_not_remote():
    assert is_remote("D:/repos/app") is False
    assert is_remote(".") is False
    assert is_remote("C:\\repos\\app") is False


@pytest.mark.parametrize(
    "value",
    [
        "https://github.com/ppk205/ComicReaderSite",
        "https://github.com/ppk205/ComicReaderSite.git",
        "http://gitlab.com/group/proj",
        "git@github.com:owner/repo.git",
        "owner/repo",
    ],
)
def test_remote_detection(value):
    assert is_remote(value) is True


def test_slug_from_url_strips_git_suffix():
    assert slug_from_url("https://github.com/ppk205/ComicReaderSite.git") == "ComicReaderSite"
    assert slug_from_url("https://github.com/owner/repo") == "repo"
    assert slug_from_url("git@github.com:owner/nested-repo.git") == "nested-repo"


def test_resolve_local_returns_local_source(tmp_path):
    repo = make_git_repo(tmp_path / "app")
    source = resolve_source(str(repo), tmp_path / "checkouts")
    assert isinstance(source, LocalSource)
    assert Path(source.checkout) == repo.resolve()
    assert len(source.commit) == 40


def test_resolve_local_rejects_missing_dir(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        resolve_source(str(tmp_path / "nope"), tmp_path / "checkouts")


def test_resolve_local_rejects_file(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="not a repository folder"):
        resolve_source(str(target), tmp_path / "checkouts")


def test_resolve_remote_clones_into_workdir(tmp_path):
    fake = FakeCommand()
    source = resolve_source(
        "https://github.com/ppk205/ComicReaderSite",
        tmp_path / "checkouts",
        run=fake,
    )
    assert isinstance(source, RemoteSource)
    assert source.repo_url == "https://github.com/ppk205/ComicReaderSite.git"
    assert Path(source.checkout) == (tmp_path / "checkouts" / "ComicReaderSite").resolve()
    assert source.commit == "a" * 40
    assert fake.cloned()


def test_resolve_remote_slug_is_expanded_to_github_url(tmp_path):
    source = resolve_source("owner/repo", tmp_path / "checkouts", run=FakeCommand())
    assert source.repo_url == "https://github.com/owner/repo.git"


def test_resolve_remote_rejects_non_repo_slug(tmp_path):
    with pytest.raises(ValueError):
        resolve_source("just-a-word", tmp_path / "checkouts")


def test_resolve_remote_pins_commit_when_given(tmp_path):
    fake = FakeCommand(commit="b" * 40)
    source = resolve_source("owner/repo", tmp_path / "checkouts", commit="b" * 40, run=fake)
    assert source.commit == "b" * 40
    assert not fake.cloned()
    assert any(c[:2] == ["git", "fetch"] for c in fake.calls)


def test_resolve_remote_reuses_existing_checkout(tmp_path):
    workdir = tmp_path / "checkouts"
    first = resolve_source("owner/repo", workdir, run=FakeCommand())
    second = resolve_source("owner/repo", workdir, run=FakeCommand())
    assert not second.reused is False
    assert Path(first.checkout) == Path(second.checkout)
    assert not FakeCommand().cloned()


def test_clone_failure_is_reported_with_stderr(tmp_path):
    def failing(argv, *, cwd=None, timeout=None, env=None, input_text=None):
        if argv[:2] == ["git", "clone"]:
            return _Result(False, "", "fatal: repository not found")
        return _Result(True, "")

    with pytest.raises(ValueError, match="repository not found"):
        resolve_source("owner/missing", tmp_path / "checkouts", run=failing)


def test_uncommitted_local_repo_is_still_scannable(tmp_path):
    repo = make_git_repo(tmp_path / "r")
    (repo / "B.java").write_text("class B {}", encoding="utf-8")
    source = resolve_source(str(repo), tmp_path / "checkouts")
    assert Path(source.checkout).exists()
    assert len(source.commit) == 40
