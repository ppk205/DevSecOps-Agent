"""Source isolation and strict single-file patch regressions (FR-02/19/49)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import httpx
import pytest

from vulnscan.ai import fix
from vulnscan.contracts.provider import ProviderProfile, ProviderUsage
from vulnscan.providers.budget import BudgetExhausted, BudgetManager


def patch(path: str = "app.py", body: str = "@@ -1 +1 @@\n-old\n+new\n") -> str:
    return f"--- a/{path}\n+++ b/{path}\n{body}"


@pytest.mark.parametrize(
    "name",
    [
        "../outside.py",
        "/absolute.py",
        "C:foo",
        "C:/foo",
        "C:\\foo",
        "//server/share/file",
        "\\\\server\\share\\file",
        "dir\\app.py",
        "app.py:stream",
        ".env",
        ".env.local",
        ".secrets",
        "dir/.ENV.prod",
        "dir/.secrets/file",
        "dir/../app.py",
        "./app.py",
        "dir//app.py",
        "app.py\x00",
        "app.py\tbad",
    ],
)
def test_rejects_unsafe_paths_before_read_or_write(tmp_path, name):
    source = tmp_path / "repo"
    source.mkdir()
    overlay = tmp_path / "overlay"
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), name, overlay)
    assert not overlay.exists()
    with pytest.raises(ValueError):
        fix.apply_unified_diff(source, patch(name))


@pytest.mark.parametrize(
    "where", ["source-parent", "source-file", "source-root", "dest-parent", "dest-root"]
)
def test_rejects_symlink_components(tmp_path, where):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "dir").mkdir()
    original = source / "dir/app.py"
    original.write_bytes(b"old\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "app.py").write_bytes(b"old\n")
    overlay = tmp_path / "overlay"
    if where == "source-parent":
        source = elsewhere
        (source / "dir").symlink_to(tmp_path / "repo/dir", target_is_directory=True)
    elif where == "source-file":
        original.unlink()
        original.symlink_to(elsewhere / "app.py")
    elif where == "source-root":
        source = tmp_path / "source-link"
        source.symlink_to(tmp_path / "repo", target_is_directory=True)
    elif where == "dest-parent":
        (tmp_path / "dest-link").symlink_to(elsewhere, target_is_directory=True)
        overlay = tmp_path / "dest-link/overlay"
    else:
        overlay.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), "dir/app.py", overlay)
    assert (elsewhere / "app.py").read_bytes() == b"old\n"


def test_apply_rejects_symlink_parent(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_bytes(b"old\n")
    root = tmp_path / "overlay"
    root.mkdir()
    (root / "dir").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        fix.apply_unified_diff(root, patch("dir/app.py"))
    assert (outside / "app.py").read_bytes() == b"old\n"


@pytest.mark.parametrize("destination", ["same", "inside", "ancestor", "existing"])
def test_overlay_requires_new_separate_attempt_root(tmp_path, destination):
    source = tmp_path / "repo"
    source.mkdir()
    original = source / "app.py"
    original.write_bytes(b"old\n")
    root = {
        "same": source,
        "inside": source / "overlay",
        "ancestor": tmp_path,
        "existing": tmp_path / "existing",
    }[destination]
    if destination == "existing":
        root.mkdir()
        (root / "app.py").write_bytes(b"retained\n")
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), "app.py", root)
    assert original.read_bytes() == b"old\n"
    if destination == "existing":
        assert (root / "app.py").read_bytes() == b"retained\n"


@pytest.mark.parametrize(
    "diff",
    [
        patch(body="@@ -1,2 +1 @@\n-old\n+new\n"),
        patch(body="@@ -1 +2 @@\n-old\n+new\n"),
        patch(body="@@ -1 +1 @@\n-old\n+new\ninvalid\n"),
        patch(body="@@ -1 +1 @@\n-old\n+new\n@@ -1 +1 @@\n-old\n+new\n"),
        patch(body="@@ -1 +1 @@\n goodbye\n"),
        patch() + patch(),
        "--- a/other.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n",
        "--- /dev/null\n+++ b/app.py\n@@ -0,0 +1 @@\n+new\n",
        "--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n",
        "diff --git a/app.py b/new.py\nrename from app.py\nrename to new.py\n" + patch(),
        "GIT binary patch\nliteral 1\n" + patch(),
        patch(
            body="@@ -1 +1 @@\n-old\n+new\n\\ No newline at end of file\n\\ No newline at end of file\n"
        ),
        patch(body="@@ -0,0 +1 @@\n+new\n") + "x" * (256 * 1024),
    ],
    ids=lambda value: "oversize-diff" if len(value) > 1000 else None,
)
def test_malformed_or_unsupported_diff_leaves_bytes_untouched(tmp_path, diff):
    (tmp_path / "app.py").write_bytes(b"old\n")
    with pytest.raises(ValueError):
        fix.apply_unified_diff(tmp_path, diff)
    assert (tmp_path / "app.py").read_bytes() == b"old\n"


@pytest.mark.parametrize(
    "before,after",
    [
        (b"old\r\nkeep\r\n", b"new\r\nkeep\r\n"),
        (b"\xef\xbb\xbfold\r\nkeep\r\n", b"\xef\xbb\xbfnew\r\nkeep\r\n"),
        (b"old\nkeep", b"new\nkeep"),
        (b"\xef\xbb\xbfold\n", b"\xef\xbb\xbfnew\n"),
    ],
)
def test_preserves_bom_line_endings_and_final_newline(tmp_path, before, after):
    (tmp_path / "app.py").write_bytes(before)
    fix.apply_unified_diff(tmp_path, patch())
    assert (tmp_path / "app.py").read_bytes() == after


@pytest.mark.parametrize(
    "data",
    [b"\xffold\n", b"old\rkeep\n", b"old\nkeep\r\n", b"old\x00\n", b"old\n" + b"x" * (1024 * 1024)],
    ids=lambda value: "oversize-file" if len(value) > 1000 else None,
)
def test_rejects_encoding_newline_binary_and_file_limit(tmp_path, data):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_bytes(data)
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), "app.py", tmp_path / "overlay")
    with pytest.raises(ValueError):
        fix.apply_unified_diff(source, patch())
    assert (source / "app.py").read_bytes() == data


def test_recorded_hash_required_when_supplied(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_bytes(b"old\n")
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), "app.py", tmp_path / "bad", expected_sha256="0" * 64)
    assert not (tmp_path / "bad").exists()
    overlay = fix.prepare_overlay(
        str(source),
        "app.py",
        tmp_path / "good",
        expected_sha256=hashlib.sha256(b"old\n").hexdigest(),
    )
    assert (overlay / "app.py").read_bytes() == b"old\n"


def test_pristine_file_bytes_survive_apply_and_failure(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    original = source / "app.py"
    before = b"old\r\n"
    original.write_bytes(before)
    overlay = fix.prepare_overlay(str(source), "app.py", tmp_path / "overlay")
    fix.apply_unified_diff(overlay, patch())
    with pytest.raises(ValueError):
        fix.apply_unified_diff(overlay, patch())
    assert original.read_bytes() == before


def test_safe_multiple_hunks_and_env_example(tmp_path):
    (tmp_path / ".env.example").write_bytes(b"old\nkeep\nlast\n")
    fix.apply_unified_diff(
        tmp_path, patch(".env.example", "@@ -1 +1 @@\n-old\n+new\n@@ -3 +3 @@\n-last\n+end\n")
    )
    assert (tmp_path / ".env.example").read_bytes() == b"new\nkeep\nend\n"


@pytest.mark.parametrize(
    "secret", ["sk-FAKEONLY123456789", "password=synthetic-value", "[REDACTED]"]
)
def test_secret_bearing_patch_is_rejected_without_mutation(tmp_path, secret):
    (tmp_path / "app.py").write_bytes(b"old\n")
    with pytest.raises(ValueError):
        fix.apply_unified_diff(tmp_path, patch(body=f"@@ -1 +1 @@\n-old\n+{secret}\n"))
    assert (tmp_path / "app.py").read_bytes() == b"old\n"


@pytest.fixture
def fake_provider(monkeypatch):
    profile = ProviderProfile(
        id="synthetic",
        label="Synthetic",
        protocol="openai_chat_completions",
        base_url="https://synthetic.invalid/v1",
        api_key_env="TASK1_SYNTHETIC_API_KEY",
        default_model="requested",
        max_retries=0,
    )
    monkeypatch.setattr(fix, "load_profile", lambda profile_id: profile)
    from vulnscan.providers import client

    monkeypatch.setattr(client, "load_api_key", lambda name: "synthetic-test-key")
    calls = []
    returned = {
        "model": "actually-returned",
        "usage": {"prompt_tokens": 12, "completion_tokens": 9, "total_tokens": 21},
        "choices": [
            {"message": {"content": "```diff\n" + patch() + "```"}, "finish_reason": "stop"}
        ],
    }
    transport = httpx.MockTransport(
        lambda request: calls.append(request) or httpx.Response(200, json=returned)
    )
    real_client = httpx.Client
    monkeypatch.setattr(
        client.httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs)
    )
    return calls, returned


def test_provider_preserves_returned_model_usage_and_profile(fake_provider):
    proposal = fix.propose_fix({}, "synthetic", "requested", 2000, "")
    assert proposal.model == "actually-returned"
    assert proposal.usage == {"prompt_tokens": 12, "completion_tokens": 9, "total_tokens": 21}
    assert proposal.profile_id == "synthetic"
    assert not hasattr(proposal, "cost_usd")


def test_missing_usage_is_unavailable(fake_provider):
    fake_provider[1].pop("usage")
    proposal = fix.propose_fix({}, "synthetic")
    assert proposal.usage is None


def test_exhausted_budget_prevents_http(fake_provider):
    budget = BudgetManager(total_usd=1, reserve_usd=0.1)
    from datetime import UTC, datetime

    budget.record(
        ProviderUsage(
            provider_id="synthetic",
            model="requested",
            timestamp=datetime.now(UTC),
            cost_usd=1,
            succeeded=True,
            run_id="",
        )
    )
    with pytest.raises(BudgetExhausted):
        fix.propose_fix({}, "synthetic", budget=budget)
    assert fake_provider[0] == []


def test_default_budget_is_enforced_before_http(fake_provider, monkeypatch):
    monkeypatch.setattr(
        BudgetManager,
        "check",
        lambda self, estimated_cost=0: (_ for _ in ()).throw(
            BudgetExhausted("synthetic exhaustion")
        ),
    )
    with pytest.raises(BudgetExhausted):
        fix.propose_fix({}, "synthetic")
    assert fake_provider[0] == []


def test_secret_or_oversize_provider_diff_not_returned(fake_provider):
    for diff in (
        patch(body="@@ -1 +1 @@\n-old\n+sk-FAKEONLY123456789\n"),
        patch() + "x" * (256 * 1024),
    ):
        fake_provider[1]["choices"][0]["message"]["content"] = "```diff\n" + diff + "```"
        with pytest.raises(ValueError):
            fix.propose_fix({}, "synthetic")


@pytest.mark.parametrize("operation", ["prepare", "apply"])
def test_hardlinked_source_is_rejected(tmp_path, operation):
    source = tmp_path / "repo"
    source.mkdir()
    original = source / "app.py"
    original.write_bytes(b"old\n")
    import os

    os.link(original, tmp_path / "linked.py")
    with pytest.raises(ValueError):
        if operation == "prepare":
            fix.prepare_overlay(str(source), "app.py", tmp_path / "overlay")
        else:
            fix.apply_unified_diff(source, patch())
    assert original.read_bytes() == b"old\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor race; native Windows controls below")
def test_source_change_during_copy_is_incomplete(tmp_path, monkeypatch):
    source = tmp_path / "repo"
    source.mkdir()
    original = source / "app.py"
    original.write_bytes(b"old\n")
    real_write = os.write
    changed = False

    def changing_write(fd, data):
        nonlocal changed
        if not changed:
            changed = True
            original.write_bytes(b"changed\n")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", changing_write)
    with pytest.raises(ValueError):
        fix.prepare_overlay(
            str(source),
            "app.py",
            tmp_path / "overlay",
            expected_sha256=hashlib.sha256(b"old\n").hexdigest(),
        )
    assert original.read_bytes() == b"changed\n"


@pytest.mark.parametrize(
    "body",
    [
        "@@ -1,2 +1,2 @@\n-old\n+new\n\\ No newline at end of file\n keep\n",
        "@@ -1,2 +1,2 @@\n-old\n\\ No newline at end of file\n+new\n keep\n",
    ],
)
def test_no_newline_marker_cannot_describe_interior_lines(tmp_path, body):
    (tmp_path / "app.py").write_bytes(b"old\nkeep")
    with pytest.raises(ValueError):
        fix.apply_unified_diff(tmp_path, patch(body=body))
    assert (tmp_path / "app.py").read_bytes() == b"old\nkeep"


def test_exactly_exhausted_zero_reserve_budget_prevents_http(fake_provider):
    with pytest.raises(BudgetExhausted):
        fix.propose_fix({}, "synthetic", budget=BudgetManager(total_usd=0, reserve_usd=0))
    assert fake_provider[0] == []


def test_no_newline_markers_preserve_unterminated_replacement(tmp_path):
    (tmp_path / "app.py").write_bytes(b"old")
    fix.apply_unified_diff(
        tmp_path,
        patch(
            body="@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
        ),
    )
    assert (tmp_path / "app.py").read_bytes() == b"new"


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor race; native Windows controls below")
def test_reparse_parent_is_rejected_on_python_311(tmp_path, monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace

    source = tmp_path / "repo"
    (source / "dir").mkdir(parents=True)
    (source / "dir/app.py").write_bytes(b"old\n")
    real_open, real_fstat = os.open, os.fstat
    directory_fds = set()

    def opened(name, flags, *args, **kwargs):
        fd = real_open(name, flags, *args, **kwargs)
        if Path(name).name == "dir":
            directory_fds.add(fd)
        return fd

    def reparse_fstat(fd):
        info = real_fstat(fd)
        if fd in directory_fds:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "fstat", reparse_fstat)
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), "dir/app.py", tmp_path / "overlay")
    assert not (tmp_path / "overlay").exists()


def test_repeated_insertions_at_same_old_position_are_overlapping(tmp_path):
    (tmp_path / "app.py").write_bytes(b"old\n")
    with pytest.raises(ValueError):
        fix.apply_unified_diff(
            tmp_path, patch(body="@@ -0,0 +1 @@\n+first\n@@ -0,0 +2 @@\n+second\n")
        )
    assert (tmp_path / "app.py").read_bytes() == b"old\n"


# Round 1: aliases must fail lexically, before touching any target path.
@pytest.mark.parametrize(
    "name",
    [
        ".env ",
        ".secrets.",
        ".env.example.",
        "dir/.secrets /app.py",
        ".git./config",
        "dir /app.py",
        "dir./app.py",
        "app.py ",
        "app.py.",
        "CON",
        "con.py",
        "NUL.txt",
        "AUX",
        "PRN.log",
        "COM1",
        "COM9.py",
        "LPT1",
        "LPT9.py",
        "CONIN$",
        "CONOUT$",
        "COM\u00b9.py",
        "LPT\u00b2",
        "dir/NUL/app.py",
        "CON .txt",
    ],
)
def test_windows_aliases_rejected_before_filesystem(tmp_path, monkeypatch, name):
    source = tmp_path / "repo"
    source.mkdir()
    real_stat = Path.stat

    def forbidden(self, *args, **kwargs):
        if self.is_relative_to(tmp_path):
            raise AssertionError("filesystem operation occurred before lexical rejection")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), name, tmp_path / "overlay")
    with pytest.raises(ValueError):
        fix.apply_unified_diff(source, patch(name))


@pytest.mark.parametrize("where", ["source", "overlay"])
@pytest.mark.parametrize("name", [".secrets.", ".env ", ".git.", "CON", "directory.", "directory "])
def test_root_aliases_rejected_before_filesystem(tmp_path, monkeypatch, where, name):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_bytes(b"old\n")
    overlay = tmp_path / "overlay"
    if where == "source":
        source = tmp_path / name
    else:
        overlay = tmp_path / name / "attempt"
    real_stat = Path.stat

    def forbidden(self, *args, **kwargs):
        if self.is_relative_to(tmp_path):
            raise AssertionError("root alias reached filesystem")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), "app.py", overlay)


@pytest.mark.parametrize("value", [None, "", "   "])
def test_omitted_or_empty_wire_model_remains_unavailable(fake_provider, value):
    wire = fake_provider[1]
    if value is None:
        wire.pop("model")
    else:
        wire["model"] = value
    proposal = fix.propose_fix({}, "synthetic", "requested")
    assert proposal.model is None
    assert proposal.usage == {"prompt_tokens": 12, "completion_tokens": 9, "total_tokens": 21}


@pytest.mark.parametrize(
    "before,body,after",
    [
        (b"--counter;\n", "@@ -1 +1 @@\n---counter;\n+++counter;\n", b"++counter;\n"),
        (b"++counter;\n", "@@ -1 +1 @@\n-++counter;\n+--counter;\n", b"--counter;\n"),
        (b"old\n", "@@ -1 +1 @@\n-old\n+++counter;\n", b"++counter;\n"),
    ],
)
def test_increment_decrement_payload_is_not_a_header(tmp_path, before, body, after):
    (tmp_path / "app.py").write_bytes(before)
    assert fix.apply_unified_diff(tmp_path, patch(body=body)) == ["app.py"]
    assert (tmp_path / "app.py").read_bytes() == after


def test_extra_headers_inside_hunk_still_rejected(tmp_path):
    (tmp_path / "app.py").write_bytes(b"old\n")
    with pytest.raises(ValueError):
        fix.apply_unified_diff(
            tmp_path, patch(body="@@ -1,2 +1,2 @@\n-old\n+new\n--- a/other.py\n+++ b/other.py\n")
        )
    assert (tmp_path / "app.py").read_bytes() == b"old\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor race; native Windows controls below")
def test_source_parent_swap_never_reads_outside(tmp_path, monkeypatch):
    import os

    source = tmp_path / "repo"
    (source / "dir").mkdir(parents=True)
    (source / "dir/app.py").write_bytes(b"old\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_bytes(b"outside-sentinel\n")
    real_open = os.open
    swapped = False
    reads = []
    outside_opened = []
    outside_identity = (outside / "app.py").stat()
    real_read = os.read

    def racing_open(name, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and Path(name).name == "app.py" and not flags & os.O_CREAT:
            swapped = True
            (source / "dir").rename(source / "parked")
            (source / "dir").symlink_to(outside, target_is_directory=True)
        fd = real_open(name, flags, *args, **kwargs)
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (outside_identity.st_dev, outside_identity.st_ino):
            outside_opened.append(fd)
        return fd

    def observed_read(fd, count):
        data = real_read(fd, count)
        reads.append(data)
        return data

    monkeypatch.setattr(os, "open", racing_open)
    monkeypatch.setattr(os, "read", observed_read)
    try:
        overlay = fix.prepare_overlay(str(source), "dir/app.py", tmp_path / "overlay")
    except ValueError:
        pass
    else:
        assert (overlay / "dir/app.py").read_bytes() == b"old\n"
    assert swapped
    assert outside_opened == []
    assert all(b"outside-sentinel" not in data for data in reads)
    assert (outside / "app.py").read_bytes() == b"outside-sentinel\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX dir_fd race; native Windows controls below")
@pytest.mark.parametrize("operation", ["mkdir", "temporary", "replace"])
def test_destination_parent_swap_never_writes_outside(tmp_path, monkeypatch, operation):
    import os

    source = tmp_path / "repo"
    (source / "dir").mkdir(parents=True)
    (source / "dir/app.py").write_bytes(b"old\n")
    root = tmp_path / "container"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_bytes(b"outside-sentinel\n")
    overlay = root / "attempt"
    if operation != "mkdir":
        overlay = fix.prepare_overlay(str(source), "dir/app.py", overlay)
        watched = overlay / "dir"
        (outside / "dir").mkdir()
    else:
        watched = root
    original = getattr(os, {"mkdir": "mkdir", "temporary": "open", "replace": "replace"}[operation])
    swapped = False
    outside_created = []

    def racing(*args, **kwargs):
        nonlocal swapped
        trigger = operation == "mkdir" and Path(args[0]).name == "attempt"
        trigger |= operation == "temporary" and str(args[0]).split("/")[-1].startswith(".fix-")
        trigger |= operation == "replace"
        if trigger and not swapped:
            swapped = True
            watched.rename(watched.with_name(watched.name + "-parked"))
            watched.symlink_to(outside, target_is_directory=True)
        result = original(*args, **kwargs)
        if operation == "temporary":
            opened = Path(os.readlink(f"/proc/self/fd/{result}"))
            if opened.is_relative_to(outside):
                outside_created.append(opened)
        return result

    monkeypatch.setattr(
        os, {"mkdir": "mkdir", "temporary": "open", "replace": "replace"}[operation], racing
    )
    try:
        if operation == "mkdir":
            fix.prepare_overlay(str(source), "dir/app.py", overlay)
        else:
            fix.apply_unified_diff(overlay, patch("dir/app.py"))
    except ValueError:
        pass
    assert swapped
    assert outside_created == []
    assert sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*")) == (
        ["app.py"] if operation == "mkdir" else ["app.py", "dir"]
    )
    assert (outside / "app.py").read_bytes() == b"outside-sentinel\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor race; native Windows controls below")
def test_opened_source_descriptor_is_checked_before_read(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace

    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_bytes(b"old\n")
    real_fstat = os.fstat
    real_open = os.open
    source_fds = set()

    def observed_open(name, flags, *args, **kwargs):
        fd = real_open(name, flags, *args, **kwargs)
        if Path(name).name == "app.py" and not flags & os.O_CREAT:
            source_fds.add(fd)
        return fd

    def linked_fstat(fd):
        info = real_fstat(fd)
        if fd in source_fds:
            return SimpleNamespace(st_mode=info.st_mode, st_nlink=2, st_size=info.st_size)
        return info

    monkeypatch.setattr(os, "open", observed_open)
    monkeypatch.setattr(os, "fstat", linked_fstat)
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), "app.py", tmp_path / "overlay")
    assert not (tmp_path / "overlay").exists()


@pytest.mark.skipif(os.name != "nt", reason="Requires actual Windows handle APIs")
@pytest.mark.parametrize("operation", ["source", "mkdir", "temporary", "replace"])
def test_windows_retained_handles_block_parent_swaps(tmp_path, monkeypatch, operation):
    from vulnscan.ai import _fix_fs as fs

    source = tmp_path / "repo"
    (source / "dir").mkdir(parents=True)
    original = source / "dir/app.py"
    original.write_bytes(b"old\r\n")
    container = tmp_path / "container"
    container.mkdir()
    overlay = container / "attempt"
    if operation in ("temporary", "replace"):
        overlay = fix.prepare_overlay(str(source), "dir/app.py", overlay)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_bytes(b"outside-sentinel\n")
    watched = (
        source / "dir"
        if operation == "source"
        else (container if operation == "mkdir" else overlay / "dir")
    )
    method = {"source": "file", "mkdir": "child", "temporary": "file", "replace": "replace"}[
        operation
    ]
    original_method = getattr(fs.Directory, method)
    attempted = []

    def racing(self, *args, **kwargs):
        trigger = self.path == watched
        if operation == "source":
            trigger &= args[0] == "app.py" and not kwargs.get("create")
        elif operation == "mkdir":
            trigger &= args[0] == "attempt"
        elif operation == "temporary":
            trigger &= args[0].startswith(".fix-")
        if trigger and not attempted:
            with pytest.raises(PermissionError):
                watched.rename(watched.with_name(watched.name + "-parked"))
            attempted.append(True)
        return original_method(self, *args, **kwargs)

    monkeypatch.setattr(fs.Directory, method, racing)
    if operation in ("source", "mkdir"):
        fix.prepare_overlay(str(source), "dir/app.py", overlay)
    else:
        fix.apply_unified_diff(overlay, patch("dir/app.py"))
        assert (overlay / "dir/app.py").read_bytes() == b"new\r\n"
    assert attempted == [True]
    assert original.read_bytes() == b"old\r\n"
    assert (outside / "app.py").read_bytes() == b"outside-sentinel\n"
    assert sorted(p.name for p in outside.iterdir()) == ["app.py"]


@pytest.mark.skipif(os.name != "nt", reason="Requires actual Windows opened descriptors")
def test_windows_opened_file_fstat_precedes_data_read(tmp_path, monkeypatch):
    from types import SimpleNamespace

    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_bytes(b"old\n")
    real_fstat = os.fstat

    def linked(fd):
        info = real_fstat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_nlink=2, st_size=info.st_size)

    monkeypatch.setattr(os, "fstat", linked)
    with pytest.raises(ValueError):
        fix.prepare_overlay(str(source), "app.py", tmp_path / "overlay")
    assert not (tmp_path / "overlay").exists()


def test_missing_windows_native_api_has_no_pathname_fallback(monkeypatch):
    import ctypes

    from vulnscan.ai import _fix_fs as fs

    monkeypatch.setattr(ctypes, "WinDLL", None, raising=False)
    with pytest.raises(ValueError):
        fs._Nt()
