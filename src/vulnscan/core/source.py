"""Phân giải mục tiêu do người dùng cung cấp thành một bản Git checkout có thể quét được.

Người dùng dán bất cứ thứ gì họ có: đường dẫn cục bộ, URL GitHub hoặc slug
``owner/repo`` đơn thuần. Module này chuyển đổi mục tiêu đó thành một bản checkout cụ thể mà
phần còn lại của pipeline có thể tin cậy, do đó không cần fixture được nhập trước.

Các ràng buộc thiết kế:

- Một lần quét luôn phải được ghim vào một SHA commit thực sự — không bao giờ dùng moving ref.
- Các bản clone là shallow và được lưu cache trong thư mục làm việc để các lần quét lại có chi phí thấp.
- Các bản checkout hiện có được tái sử dụng; không clone lại hay buộc reset.
- Lỗi hiển thị stderr cơ bản của git thay vì một thông báo chung chung.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

if TYPE_CHECKING:
    from ..scanners.process import CommandResult

_COMMAND_TIMEOUT = 600


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        cwd: str | Path | None = ...,
        timeout: float | None = ...,
        env: dict[str, str] | None = ...,
        input_text: str | None = ...,
    ) -> Any: ...


@dataclass(frozen=True)
class LocalSource:
    checkout: str
    repo_url: str
    commit: str


@dataclass(frozen=True)
class RemoteSource:
    checkout: str
    repo_url: str
    commit: str
    reused: bool = False


def _default_run(
    argv: list[str],
    *,
    cwd: str | Path | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    from ..scanners.process import run_command

    return run_command(argv, cwd=cwd, timeout=timeout, env=env, input_text=input_text)


_SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_REMOTE_RE = re.compile(r"^(https?://|git@|ssh://|git://)")


def is_remote(value: str) -> bool:
    """True khi *value* có dạng một tham chiếu repository, không phải là một đường dẫn."""
    text = value.strip()
    if not text:
        return False
    if _REMOTE_RE.match(text):
        return True
    return bool(_SLUG_RE.match(text) and not Path(text).exists())


def slug_from_url(value: str) -> str:
    """Trả về tên repository không có ``.git`` từ bất kỳ dạng remote nào."""
    text = value.strip().rstrip("/")
    text = re.sub(r"\.git$", "", text, flags=re.IGNORECASE)
    name = re.split(r"[/:]", text)[-1]
    return name or "repo"


def normalise_repo_url(value: str) -> str:
    """Mở rộng dạng viết tắt và chuẩn hóa một remote thành một URL có thể clone được."""
    text = value.strip()
    if not _REMOTE_RE.match(text):
        if not _SLUG_RE.match(text):
            raise ValueError(f"'{text}' is not a repository. Use a URL or an owner/repo slug.")
        text = "https://github.com/" + text
    if re.match(r"^git@[^:]+:", text) or text.startswith("ssh://"):
        return text if text.endswith(".git") else text + ".git"
    if not text.endswith(".git"):
        text += ".git"
    return text


def _head_sha(root: Path, run: Callable[..., Any]) -> str:
    result = run(["git", "rev-parse", "HEAD"], cwd=str(root), timeout=_COMMAND_TIMEOUT)
    if not result.succeeded or not result.stdout.strip():
        raise ValueError("cannot determine the checked-out commit")
    return cast(str, result.stdout.strip())


def _fetch_commit(root: Path, repo_url: str, commit: str, run: Callable[..., Any]) -> None:
    run(["git", "init"], cwd=str(root), timeout=_COMMAND_TIMEOUT)
    run(["git", "remote", "add", "origin", repo_url], cwd=str(root), timeout=_COMMAND_TIMEOUT)
    fetched = run(
        ["git", "fetch", "--depth", "1", "origin", commit],
        cwd=str(root),
        timeout=_COMMAND_TIMEOUT,
    )
    if not fetched.succeeded:
        detail = (fetched.stderr or fetched.stdout or "").strip()
        raise ValueError(f"cannot fetch commit {commit[:12]}: {detail}")
    checked = run(["git", "checkout", "FETCH_HEAD"], cwd=str(root), timeout=_COMMAND_TIMEOUT)
    if not checked.succeeded:
        detail = (checked.stderr or checked.stdout or "").strip()
        raise ValueError(f"cannot check out commit {commit[:12]}: {detail}")


def _clone_default_branch(root: Path, repo_url: str, run: Callable[..., Any]) -> None:
    result = run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            repo_url,
            str(root),
        ],
        timeout=_COMMAND_TIMEOUT,
    )
    if not result.succeeded:
        detail = (result.stderr or result.stdout or "").strip()
        raise ValueError(f"clone failed for {repo_url}: {detail}")


def resolve_source(
    value: str,
    workdir: str | Path = "harness",
    *,
    commit: str = "",
    run: Callable[..., Any] | None = None,
) -> LocalSource | RemoteSource:
    """Chuyển đổi một mục tiêu người dùng thành một bản checkout cụ thể được ghim commit.

    Parameters
    ----------
    value:
        Thư mục cục bộ, URL từ xa, hoặc slug ``owner/repo``.
    workdir:
        Thư mục bộ nhớ đệm cho các repository đã clone.
    commit:
        Commit được ghim tùy chọn. Khi bị bỏ qua, HEAD nhánh mặc định của remote
        sẽ được sử dụng và SHA đã phân giải đó được ghi lại.
    """
    runner = run or _default_run
    text = value.strip()
    if not text:
        raise ValueError("enter a repository URL or a local folder path")

    if not is_remote(text):
        root = Path(text).expanduser()
        if not root.exists():
            raise ValueError(f"'{text}' does not exist and is not a repository URL")
        if not root.is_dir():
            raise ValueError(f"'{text}' is a file, not a repository folder")
        resolved = root.resolve()
        commit_sha = commit or _head_sha(resolved, runner)
        return LocalSource(str(resolved), str(resolved), commit_sha)

    repo_url = normalise_repo_url(text)
    name = slug_from_url(repo_url)
    cache = Path(workdir).expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True)
    root = cache / name

    if (root / ".git").is_dir():
        commit_sha = commit or _head_sha(root, runner)
        if commit and commit_sha != commit and not commit.startswith(commit_sha):
            _fetch_commit(root, repo_url, commit, runner)
            commit_sha = _head_sha(root, runner)
        return RemoteSource(str(root), repo_url, commit_sha, reused=True)

    if commit:
        root.mkdir(parents=True, exist_ok=True)
        _fetch_commit(root, repo_url, commit, runner)
    else:
        _clone_default_branch(root, repo_url, runner)
    return RemoteSource(str(root), repo_url, _head_sha(root, runner))
