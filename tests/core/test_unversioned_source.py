"""FR-01/02, QR-20: filesystem snapshots without a committed Git revision."""

import pytest

from vulnscan.core.config import ScanConfig
from vulnscan.core.scan_service import checkout_manifest
from vulnscan.scanners.process import CommandResult


@pytest.fixture
def plain_source(tmp_path, monkeypatch):
    folder = tmp_path / "plain source"
    folder.mkdir()
    (folder / "Example.java").write_text("class Example {}", encoding="utf-8")
    calls = []

    def no_git(argv, **kwargs):
        calls.append(argv)
        return CommandResult(127, stderr="command not found: git")

    monkeypatch.setattr("vulnscan.core.scan_service.run_command", no_git)
    return folder, calls


def test_fr01_no_git_folder_has_hashes_and_an_explicit_revision_gap(plain_source):
    folder, calls = plain_source
    manifest = checkout_manifest(str(folder), ScanConfig())
    assert manifest["commit"] == "no-revision"
    assert manifest["dirty"] is None
    assert manifest["revision_reason"]
    assert manifest["inventory"] == ["Example.java"]
    assert len(manifest["files"]["Example.java"]) == 64
    assert not any(argv[1] in {"status", "ls-files"} for argv in calls)
    (folder / "Example.java").write_text("class Changed {}", encoding="utf-8")
    changed = checkout_manifest(str(folder), ScanConfig())
    assert changed["files"] != manifest["files"]


@pytest.mark.parametrize(
    "configuration,expected", [(ScanConfig(ci=True), ""), (ScanConfig(), "a" * 40)]
)
def test_fr01_unversioned_source_cannot_satisfy_ci_or_a_commit_pin(
    plain_source, configuration, expected
):
    folder, _ = plain_source
    with pytest.raises(ValueError, match="revision|commit"):
        checkout_manifest(str(folder), configuration, expected)


def test_fr02_unversioned_enumeration_excludes_credentials_and_runtime(plain_source):
    folder, _ = plain_source
    # Empty placeholders only; no credential values are created or inspected.
    for name in (".env", ".env.local", ".secrets"):
        (folder / name).touch()
    for name in (".git", ".venv", "node_modules", ".devsec"):
        (folder / name).mkdir()
        (folder / name / "Ignored.java").touch()
    output = folder / "reports"
    output.mkdir()
    (output / "generated.java").touch()
    manifest = checkout_manifest(str(folder), ScanConfig(), excluded=[output])
    assert set(manifest["files"]) == {"Example.java"}


def test_fr01_unversioned_enumeration_enforces_file_limit(plain_source):
    folder, _ = plain_source
    (folder / "Other.java").touch()
    with pytest.raises(ValueError, match="max_files"):
        checkout_manifest(str(folder), ScanConfig(max_files=1))


def test_fr02_unversioned_enumeration_refuses_symlink_escape(plain_source, tmp_path):
    folder, _ = plain_source
    external = tmp_path / "outside.java"
    external.write_text("external", encoding="utf-8")
    try:
        (folder / "escape.java").symlink_to(external)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    with pytest.raises(ValueError, match="symlink"):
        checkout_manifest(str(folder), ScanConfig())


def test_fr01_plain_folder_with_git_installed_still_has_no_revision(tmp_path):
    folder = tmp_path / "plain"
    folder.mkdir()
    (folder / "A.java").touch()
    assert checkout_manifest(str(folder), ScanConfig())["commit"] == "no-revision"


def test_fr01_empty_local_git_repository_has_no_revision(tmp_path):
    import subprocess

    folder = tmp_path / "unborn"
    folder.mkdir()
    subprocess.run(["git", "init", str(folder)], capture_output=True, check=True)
    (folder / "A.java").touch()
    manifest = checkout_manifest(str(folder), ScanConfig())
    assert manifest["commit"] == "no-revision"
    assert manifest["inventory"] == ["A.java"]


def test_fr02_git_worktree_pointer_is_not_copied_when_git_is_unavailable(plain_source):
    folder, _ = plain_source
    (folder / ".git").write_text("gitdir: /unavailable/worktree", encoding="utf-8")
    manifest = checkout_manifest(str(folder), ScanConfig())
    assert ".git" not in manifest["files"]
