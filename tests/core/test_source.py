"""TDD: any repo can be scanned — local path, GitHub URL, or owner/repo slug."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulnscan.core.source import (
    LocalSource,
    RemoteSource,
    is_remote,
    normalise_repo_url,
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
            metadata = Path(argv[-1]) / ".git"
            metadata.mkdir(parents=True, exist_ok=True)
            (metadata / "test-origin").write_text(argv[-2], encoding="utf-8")
        if argv[:2] == ["git", "init"]:
            (Path(str(cwd)) / ".git").mkdir(parents=True, exist_ok=True)
        if argv[:3] == ["git", "rev-parse", "HEAD"]:
            return _Result(True, self.commit + "\n")
        if argv[:4] == ["git", "remote", "add", "origin"]:
            (Path(cwd) / ".git" / "test-origin").write_text(argv[-1], encoding="utf-8")
        if argv[:4] == ["git", "remote", "get-url", "origin"]:
            return _Result(True, (Path(cwd) / ".git" / "test-origin").read_text(encoding="utf-8"))
        if argv[:2] == ["git", "fetch"]:
            self.commit = argv[-1]
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
    assert Path(source.checkout).parent == (tmp_path / "checkouts").resolve()
    assert Path(source.checkout).name.startswith("ComicReaderSite-")
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


@pytest.mark.parametrize(
    "value",
    [
        "./missing",
        "../missing",
        "missing/..",
        "missing/.",
        ".\\missing",
        "..\\missing",
        "/missing/project",
        "C:/missing/project",
        "C:\\missing\\project",
        "\\\\server\\share",
    ],
)
def test_fr01_explicit_local_paths_never_become_remote(value, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert not is_remote(value)


def test_fr01_existing_owner_repo_directory_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "owner" / "repo").mkdir(parents=True)
    assert not is_remote("owner/repo")


@pytest.mark.parametrize("quote", ["'", '"'])
def test_fr01_quoted_paths_with_spaces_resolve_locally(tmp_path, quote):
    folder = tmp_path / "source folder"
    folder.mkdir()
    source = resolve_source(f"{quote}{folder}{quote}", run=FakeCommand())
    assert isinstance(source, LocalSource)
    assert source.checkout == str(folder)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://github.com/owner/repo/", "https://github.com/owner/repo.git"),
        ('"https://github.com/owner/repo.git"', "https://github.com/owner/repo.git"),
        ("HTTPS://github.com/owner/repo", "https://github.com/owner/repo.git"),
        ("ssh://git@example.test/group/repo/", "ssh://git@example.test/group/repo.git"),
        ("git@example.test:group/repo.git", "git@example.test:group/repo.git"),
    ],
)
def test_fr01_remote_input_normalization(value, expected):
    assert is_remote(value)
    assert normalise_repo_url(value) == expected


@pytest.mark.parametrize(
    "value", ["https://example.test", "https:///owner/repo", "ftp://example.test/repo"]
)
def test_fr01_invalid_repository_urls_are_rejected(value, tmp_path):
    fake = FakeCommand()
    with pytest.raises(ValueError):
        resolve_source(value, tmp_path / "cache", run=fake)
    assert not fake.calls


def test_fr01_plain_folder_without_git_records_no_revision(tmp_path):
    folder = tmp_path / "plain folder"
    folder.mkdir()
    (folder / "A.java").write_text("class A {}", encoding="utf-8")

    def no_git(*args, **kwargs):
        from vulnscan.scanners.process import CommandResult

        return CommandResult(127, stderr="command not found: git")

    source = resolve_source(str(folder), run=no_git)
    assert source.checkout == str(folder)
    assert source.commit == "no-revision"
    with pytest.raises(ValueError, match="commit|revision"):
        resolve_source(str(folder), commit="b" * 40, run=no_git)


def test_fr01_missing_explicit_local_path_never_clones(tmp_path):
    fake = FakeCommand()
    with pytest.raises(ValueError, match="does not exist"):
        resolve_source("./missing", tmp_path / "cache", run=fake)
    assert not fake.calls


def test_fr01_requested_local_commit_is_verified(tmp_path):
    folder = tmp_path / "local"
    folder.mkdir()
    with pytest.raises(ValueError, match="commit"):
        resolve_source(str(folder), commit="b" * 40, run=FakeCommand(commit="a" * 40))


def test_fr01_missing_git_for_remote_has_actionable_error(tmp_path):
    def no_git(*args, **kwargs):
        from vulnscan.scanners.process import CommandResult

        return CommandResult(127, stderr="command not found: git")

    with pytest.raises(ValueError, match="Git is required"):
        resolve_source("owner/repo", tmp_path / "cache", run=no_git)


def test_fr01_remote_cache_separates_owners_with_the_same_repository_name(tmp_path):
    first = resolve_source("first/repo", tmp_path, run=FakeCommand())
    second = resolve_source("second/repo", tmp_path, run=FakeCommand())
    assert first.checkout != second.checkout
    assert first.repo_url != second.repo_url


def test_fr01_cached_remote_pin_is_checked_against_actual_head(tmp_path):
    resolve_source("owner/repo", tmp_path, run=FakeCommand())
    fake = FakeCommand()
    source = resolve_source("owner/repo", tmp_path, commit="b" * 40, run=fake)
    assert source.commit == "b" * 40
    assert any(argv[:2] == ["git", "fetch"] for argv in fake.calls)


@pytest.mark.parametrize("value", ["github.com/owner/repo", "gitlab.com/group/repo"])
def test_fr01_host_shorthand_is_a_remote_reference(value):
    assert is_remote(value)
    assert normalise_repo_url(value) == f"https://{value}.git"


@pytest.mark.parametrize(
    "value",
    ["", " ", "https://example.test/owner/repo\nother", "https://github.com/owner/repo/tree/main"],
)
def test_fr01_empty_and_invalid_inputs_do_not_run_git(value, tmp_path):
    fake = FakeCommand()
    with pytest.raises(ValueError):
        resolve_source(value, tmp_path / "cache", run=fake)
    assert not fake.calls


def test_fr01_embedded_credentials_are_rejected_without_echoing_them(tmp_path):
    fake = FakeCommand()
    with pytest.raises(ValueError, match="credentials") as error:
        resolve_source("https://user:synthetic-password@example.test/repo", tmp_path, run=fake)
    assert "synthetic-password" not in str(error.value)
    assert not fake.calls


def test_fr01_remote_cache_symlink_cannot_redirect_git_operations(tmp_path):
    cache, external = tmp_path / "cache", tmp_path / "external"
    cache.mkdir()
    external.mkdir()
    try:
        (cache / "repo").symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    fake = FakeCommand()
    with pytest.raises(ValueError, match="symlink"):
        resolve_source("owner/repo", cache, run=fake)
    assert not fake.calls


def test_fr01_file_uri_is_a_local_folder_with_decoded_spaces(tmp_path):
    folder = tmp_path / "source folder"
    folder.mkdir()
    assert not is_remote(folder.as_uri())
    source = resolve_source(folder.as_uri(), run=FakeCommand())
    assert isinstance(source, LocalSource)
    assert source.checkout == str(folder)


def test_fr01_unknown_home_directory_is_an_input_error(monkeypatch):
    def unknown_home(self):
        raise RuntimeError("home unavailable")

    monkeypatch.setattr(Path, "expanduser", unknown_home)
    with pytest.raises(ValueError, match="absolute folder"):
        resolve_source("~/project", run=FakeCommand())


@pytest.mark.parametrize("ignored", [False, True])
def test_fr01_untracked_folder_does_not_inherit_an_unrelated_parent_commit(tmp_path, ignored):
    from vulnscan.core.config import ScanConfig
    from vulnscan.core.scan_service import checkout_manifest

    parent = make_git_repo(tmp_path / "parent")
    if ignored:
        (parent / ".gitignore").write_text("downloaded/\n", encoding="utf-8")
    folder = parent / "downloaded" / "plain source"
    folder.mkdir(parents=True)
    (folder / "Example.java").write_text("class Example {}", encoding="utf-8")
    source = resolve_source(str(folder))
    assert source.commit == "no-revision"
    manifest = checkout_manifest(str(folder), ScanConfig())
    assert manifest["inventory"] == ["Example.java"]


def test_fr01_tracked_subfolder_retains_its_real_parent_revision(tmp_path):
    parent = tmp_path / "parent"
    (parent / "nested").mkdir(parents=True)
    make_git_repo(parent, "nested/A.java")
    source = resolve_source(str(parent / "nested"))
    assert len(source.commit) == 40


@pytest.mark.parametrize("commit", ["HEAD", "main", "--upload-pack=unexpected"])
def test_fr01_commit_pin_must_be_a_sha_not_a_ref_or_git_option(tmp_path, commit):
    fake = FakeCommand()
    with pytest.raises(ValueError, match="commit"):
        resolve_source("owner/repo", tmp_path, commit=commit, run=fake)
    assert not fake.calls


def test_fr01_clone_url_is_separated_from_git_options(tmp_path):
    fake = FakeCommand()
    resolve_source("owner/repo", tmp_path, run=fake)
    command = next(argv for argv in fake.calls if argv[:2] == ["git", "clone"])
    assert command[command.index("--") + 1] == "https://github.com/owner/repo.git"
