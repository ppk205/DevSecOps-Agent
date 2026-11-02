"""Baseline fix boundaries, using fake providers and scanners only."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnscan.ai import fix
from vulnscan.contracts.enums import ProviderProtocol
from vulnscan.contracts.provider import ProviderProfile


def _finding(path: str = "app.py") -> dict:
    return {
        "finding_id": "test-finding",
        "observations": [{"rule_id": "py-sql-injection", "location": {"file_path": path}}],
    }


def _diff(path: str = "app.py") -> str:
    return f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:
        pytest.skip(f"Symlinks unavailable: {exc}")


@pytest.mark.parametrize("path", ["../outside.py", r"..\outside.py", "C:/outside.py"])
def test_overlay_rejects_nonrelative_paths(tmp_path: Path, path: str) -> None:
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (tmp_path / "outside.py").write_text("old\n")
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(checkout), path, tmp_path / "overlay")


def test_overlay_rejects_absolute_file(tmp_path: Path) -> None:
    checkout = tmp_path / "repo"
    checkout.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("old\n")
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(checkout), str(outside), tmp_path / "overlay")


@pytest.mark.parametrize("destination_link", [False, True])
def test_overlay_rejects_link_escapes(tmp_path: Path, destination_link: bool) -> None:
    checkout = tmp_path / "repo"
    checkout.mkdir()
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("old\n")
    if destination_link:
        (checkout / "app.py").write_text("source\n")
        _symlink(overlay / "app.py", outside)
    else:
        _symlink(checkout / "app.py", outside)
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(checkout), "app.py", overlay)
    assert outside.read_text() == "old\n"


def test_overlay_rejects_destination_hardlink(tmp_path: Path) -> None:
    checkout = tmp_path / "repo"
    checkout.mkdir()
    original = checkout / "app.py"
    original.write_text("old\n")
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    os.link(original, overlay / "app.py")
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(checkout), "app.py", overlay)
    assert original.read_text() == "old\n"


@pytest.mark.parametrize("suffix", ["", "overlay"])
def test_overlay_cannot_be_the_checkout(tmp_path: Path, suffix: str) -> None:
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "app.py").write_text("old\n")
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(checkout), "app.py", checkout / suffix)
    assert (checkout / "app.py").read_text() == "old\n"


@pytest.mark.parametrize("hardlink", [False, True])
def test_apply_does_not_write_linked_files(tmp_path: Path, hardlink: bool) -> None:
    original = tmp_path / "original.py"
    original.write_text("old\n")
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    if hardlink:
        os.link(original, overlay / "app.py")
    else:
        _symlink(overlay / "app.py", original)
    with pytest.raises(ValueError):
        fix.apply_unified_diff(overlay, _diff())
    assert original.read_text() == "old\n"


@pytest.mark.parametrize("operation", ["copy", "patch"])
def test_overlay_root_cannot_alias_checkout(tmp_path: Path, operation: str) -> None:
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "app.py").write_text("old\n")
    alias = tmp_path / "alias"
    _symlink(alias, checkout)
    with pytest.raises(ValueError):
        if operation == "copy":
            fix.prepare_overlay(str(checkout), "app.py", alias)
        else:
            fix.apply_unified_diff(alias, _diff())
    assert (checkout / "app.py").read_text() == "old\n"


@pytest.mark.parametrize(
    "diff",
    [
        _diff().replace("--- a/app.py", "--- a/other.py"),
        _diff().replace("@@ -1 +1 @@", "@@ -1,2 +1,2 @@"),
        _diff() + _diff("other.py"),
    ],
)
def test_apply_rejects_ambiguous_or_malformed_diff(tmp_path: Path, diff: str) -> None:
    (tmp_path / "app.py").write_text("old\n")
    (tmp_path / "other.py").write_text("old\n")
    with pytest.raises(ValueError):
        fix.apply_unified_diff(tmp_path, diff)
    assert (tmp_path / "app.py").read_text() == "old\n"
    assert (tmp_path / "other.py").read_text() == "old\n"


@pytest.mark.parametrize(
    ("returncode", "output"),
    [
        (2, '{"results": [], "errors": []}'),
        (7, '{"results": [], "errors": []}'),
        (0, ""),
        (0, "{}"),
        (0, "[]"),
        (0, "null"),
        (0, '{"results": null}'),
        (0, '{"results": [null]}'),
        (0, '{"results": [{}]}'),
        (0, '{"results": [], "errors": [{"message": "parse failed"}]}'),
        (0, '{"results": [], "errors": [], "paths": {"scanned": []}}'),
        (0, '{"results": [], "errors": []}'),
    ],
)
def test_verify_never_treats_incomplete_scan_as_fixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, returncode: int, output: str
) -> None:
    (tmp_path / "app.py").write_text("old\n")
    monkeypatch.setattr(
        fix.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=returncode, stdout=output),
    )
    result = fix.verify_fixed(tmp_path, "app.py", "py-sql-injection", 1)
    assert result["fixed"] is False
    assert result["detail"]


@pytest.mark.parametrize(
    "error", [FileNotFoundError("missing"), subprocess.TimeoutExpired("scan", 1)]
)
def test_verify_reports_scanner_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    (tmp_path / "app.py").write_text("old\n")

    def unavailable(*args, **kwargs):
        raise error

    monkeypatch.setattr(fix.subprocess, "run", unavailable)
    result = fix.verify_fixed(tmp_path, "app.py", "py-sql-injection", 1)
    assert result["fixed"] is False


def test_verify_catches_refire_shifted_by_patch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "app.py"
    path.write_text("old\n")
    output = json.dumps(
        {
            "results": [{"check_id": "rules.py-sql-injection", "start": {"line": 9}}],
            "errors": [],
            "paths": {"scanned": [str(path)]},
        }
    )
    monkeypatch.setattr(
        fix.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=output)
    )
    assert fix.verify_fixed(tmp_path, "app.py", "py-sql-injection", 1)["fixed"] is False


def test_fix_prompt_redacts_and_wraps_source() -> None:
    secret = "sk-" + "x" * 30  # Synthetic key-shaped fixture, not a credential.
    finding = _finding('app.py" bogus="attribute')
    finding["title"] = secret
    finding["observations"][0]["location"]["snippet"] = "old " + secret
    prompt = fix.build_fix_prompt(finding, "1| context " + secret)
    assert secret not in prompt
    assert "[REDACTED]" in prompt
    assert prompt.count('<untrusted_code path="app.py&quot; bogus=&quot;attribute">') == 2
    assert prompt.count("</untrusted_code>") == 2


def _profile(url: str) -> ProviderProfile:
    return ProviderProfile(
        id="test-profile",
        label="Local label is not consent",
        protocol=ProviderProtocol.OPENAI_COMPATIBLE,
        base_url=url,
        api_key_env="",
        default_model="test-model",
        metadata={"local": True},
    )


def test_propose_rejects_cloud_before_constructing_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fix, "load_profile", lambda _: _profile("https://cloud.invalid/v1"))

    def unexpected_client(*args, **kwargs):
        raise AssertionError("Provider must not be initialized without consent")

    monkeypatch.setattr(fix, "ProviderClient", unexpected_client)
    with pytest.raises(ValueError, match="allow-cloud-model"):
        fix.propose_fix(_finding(), "test-profile")


@pytest.mark.parametrize("url", ["http://127.0.0.1:1234/v1", "https://cloud.invalid/v1"])
def test_propose_redacts_provider_boundary(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    secret = "sk-" + "x" * 30
    finding = _finding()
    finding["observations"][0]["location"]["snippet"] = secret
    monkeypatch.setattr(fix, "load_profile", lambda _: _profile(url))

    def chat(messages, **kwargs):
        assert all(secret not in message.content for message in messages)
        assert '<untrusted_code path="app.py">' in messages[1].content
        return SimpleNamespace(content="```diff\n" + _diff().replace("new", secret) + "```")

    monkeypatch.setattr(fix, "ProviderClient", lambda _: SimpleNamespace(chat=chat))
    proposal = fix.propose_fix(finding, "test-profile", allow_cloud_model=url.startswith("https"))
    assert secret not in proposal.diff_text
    assert "[REDACTED]" in proposal.diff_text


def test_propose_redacts_provider_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "sk-" + "x" * 30
    monkeypatch.setattr(fix, "load_profile", lambda _: _profile("http://localhost:1234/v1"))

    def chat(*args, **kwargs):
        raise ValueError(secret)

    monkeypatch.setattr(fix, "ProviderClient", lambda _: SimpleNamespace(chat=chat))
    with pytest.raises(ValueError) as error:
        fix.propose_fix(_finding(), "test-profile")
    assert secret not in str(error.value)
    assert "[REDACTED]" in str(error.value)


def test_apply_respects_no_newline_marker(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("old")
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n"
        "-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
    )
    fix.apply_unified_diff(tmp_path, diff)
    assert (tmp_path / "app.py").read_text() == "new"
