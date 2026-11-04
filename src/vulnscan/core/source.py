"""Resolve a local source folder or repository URL into a scan target.

Users paste whatever they have: a local path, a GitHub URL, or a bare
``owner/repo`` slug. This module turns that into a concrete checkout the
rest of the pipeline can trust, so no pre-imported fixture is required.

Design constraints:

- Git sources record an actual commit; other local folders record no-revision.
- Clones are shallow and cached under a work directory so re-scans are cheap.
- Existing checkouts are reused; nothing is re-cloned or force-reset.
- Failures surface the underlying git stderr instead of a generic message.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import urlsplit, urlunsplit
from urllib.request import url2pathname

if TYPE_CHECKING:
    from ..scanners.process import CommandResult

_COMMAND_TIMEOUT = 600
NO_REVISION = "no-revision"


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
_REMOTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_SCP_RE = re.compile(r"^[^\s/@:]+@[^\s/:]+:[^\s]+$")
_HOST_RE = re.compile(r"^(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)/", re.IGNORECASE)


def _input_text(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] in {"'", '"'} and text[-1] == text[0]:
        text = text[1:-1].strip()
    if text.lower().startswith("file://"):
        parsed = urlsplit(text)
        if parsed.username or parsed.query or parsed.fragment or not parsed.path:
            raise ValueError("use a local folder file URI without credentials, query or fragment")
        host = parsed.netloc if parsed.netloc.lower() != "localhost" else ""
        text = url2pathname(("//" + host if host else "") + parsed.path)
    if any(ord(char) < 32 for char in text):
        raise ValueError("repository input must be a single path or URL without control characters")
    return text


def _expanded_path(value: str | Path) -> Path:
    try:
        return Path(value).expanduser()
    except RuntimeError as exc:
        raise ValueError("cannot expand the home directory; use an absolute folder path") from exc


def is_remote(value: str) -> bool:
    """True when *value* looks like a repository reference, not a path."""
    text = _input_text(value)
    if not text:
        return False
    if re.match(r"^[A-Za-z]:", text):
        return False
    if _REMOTE_RE.match(text) or _SCP_RE.match(text):
        return True
    if text.startswith(("/", "\\", "~")) or "\\" in text:
        return False
    if any(part in {".", ".."} for part in text.split("/")):
        return False
    if Path(text).exists():
        return False
    return bool(_SLUG_RE.fullmatch(text) or _HOST_RE.match(text))


def slug_from_url(value: str) -> str:
    """Return the repository name without ``.git`` from any remote form."""
    text = _input_text(value).rstrip("/")
    text = re.sub(r"\.git$", "", text, flags=re.IGNORECASE)
    name = re.split(r"[/:]", text)[-1]
    return name or "repo"


def normalise_repo_url(value: str) -> str:
    """Expand shorthand and normalise a remote to a clonable URL."""
    text = _input_text(value).rstrip("/")
    if _SCP_RE.fullmatch(text):
        return text if text.lower().endswith(".git") else text + ".git"
    if _HOST_RE.match(text):
        text = "https://" + text
    elif not _REMOTE_RE.match(text):
        if not _SLUG_RE.fullmatch(text) or any(part in {".", ".."} for part in text.split("/")):
            raise ValueError("use a repository URL or an owner/repo slug")
        text = "https://github.com/" + text
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in {"https", "http", "ssh", "git"}:
        raise ValueError("repository URL must use HTTPS, HTTP, SSH or Git transport")
    if not parsed.hostname or not parsed.path.strip("/") or parsed.query or parsed.fragment:
        raise ValueError("use a repository clone URL with a host and repository path")
    if parsed.password or (parsed.scheme.lower() in {"http", "https"} and parsed.username):
        raise ValueError("repository URL must not contain credentials; use a Git credential helper")
    parts = parsed.path.strip("/").split("/")
    if any(part in {".", "..", ""} for part in parts):
        raise ValueError("repository URL contains an invalid path")
    if parsed.hostname.lower() in {"github.com", "www.github.com"} and len(parts) != 2:
        raise ValueError("use the GitHub repository URL without tree, blob or issue paths")
    path = parsed.path if parsed.path.lower().endswith(".git") else parsed.path + ".git"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))


def local_revision(root: Path, run: Callable[..., Any]) -> tuple[str, str]:
    """Return a verified Git revision or an explicit, explained revision gap."""
    result = run(["git", "rev-parse", "HEAD"], cwd=str(root), timeout=_COMMAND_TIMEOUT)
    if result.succeeded and result.stdout.strip():
        if not (root / ".git").exists():
            tracked = run(
                ["git", "ls-files", "--cached", "-z"], cwd=str(root), timeout=_COMMAND_TIMEOUT
            )
            if not tracked.succeeded or not tracked.stdout.strip("\0\r\n"):
                return (
                    NO_REVISION,
                    "The selected folder has no verifiable tracked revision in its parent repository",
                )
        return str(result.stdout.strip()), ""
    reason = (
        "Git is unavailable; revision and cleanliness cannot be verified"
        if getattr(result, "returncode", None) == 127
        else "No committed Git revision is available; source files are identified by hashes"
    )
    return NO_REVISION, reason


def _require_git(result: Any) -> None:
    if getattr(result, "returncode", None) == 127:
        raise ValueError("Git is required for repository URLs; install Git or scan a local folder")


def _head_sha(root: Path, run: Callable[..., Any]) -> str:
    result = run(["git", "rev-parse", "HEAD"], cwd=str(root), timeout=_COMMAND_TIMEOUT)
    _require_git(result)
    if not result.succeeded or not result.stdout.strip():
        raise ValueError("cannot determine the checked-out commit")
    return cast(str, result.stdout.strip())


def _fetch_commit(root: Path, repo_url: str, commit: str, run: Callable[..., Any]) -> None:
    if not (root / ".git").exists():
        for argv in (["git", "init"], ["git", "remote", "add", "origin", repo_url]):
            result = run(argv, cwd=str(root), timeout=_COMMAND_TIMEOUT)
            _require_git(result)
            if not result.succeeded:
                raise ValueError("cannot initialize the repository clone cache")
    fetched = run(
        ["git", "fetch", "--depth", "1", "origin", commit],
        cwd=str(root),
        timeout=_COMMAND_TIMEOUT,
    )
    _require_git(fetched)
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
            "--",
            repo_url,
            str(root),
        ],
        timeout=_COMMAND_TIMEOUT,
    )
    _require_git(result)
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
    """Resolve repository references or hash-identifiable local source folders.

    Parameters
    ----------
    value:
        Local directory, remote URL, or ``owner/repo`` slug.
    workdir:
        Cache directory for cloned repositories.
    commit:
        Optional pinned commit. When omitted the remote's default branch HEAD
        is used, and that resolved SHA is recorded.
    """
    runner = run or _default_run
    text = _input_text(value)
    if not text:
        raise ValueError("enter a repository URL or a local folder path")
    commit = commit.strip()
    if commit and commit != NO_REVISION and not re.fullmatch(r"[0-9a-fA-F]{4,64}", commit):
        raise ValueError("commit pin must be a hexadecimal commit SHA, not a branch or Git option")

    if not is_remote(text):
        root = _expanded_path(text)
        if not root.exists():
            raise ValueError(f"'{text}' does not exist and is not a repository URL")
        if not root.is_dir():
            raise ValueError(f"'{text}' is a file, not a repository folder")
        resolved = root.resolve()
        commit_sha, _ = local_revision(resolved, runner)
        if commit and commit != NO_REVISION and commit_sha == NO_REVISION:
            raise ValueError("a commit pin requires Git and a committed local revision")
        if commit and not commit_sha.lower().startswith(commit.lower()):
            raise ValueError("requested commit does not match the local source revision")
        return LocalSource(str(resolved), str(resolved), commit_sha)

    repo_url = normalise_repo_url(text)
    if commit == NO_REVISION:
        raise ValueError("repository URLs require an actual Git commit, not no-revision")
    name = slug_from_url(repo_url)
    cache = _expanded_path(workdir).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    # Separate owners/hosts that use the same repository name. Reuse an older
    # cache directory only after its origin is checked against the requested URL.
    root = cache / f"{name}-{hashlib.sha256(repo_url.encode()).hexdigest()[:12]}"
    legacy = cache / name
    for candidate in (legacy, root):
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(cache):
            raise ValueError("repository clone cache must not escape through a symlink")
        if (candidate / ".git").is_symlink():
            raise ValueError("repository clone cache Git metadata must not be a symlink")
        if not (candidate / ".git").exists():
            continue
        if not (candidate / ".git").is_dir():
            raise ValueError("repository clone cache must be a standalone Git checkout")
        origin = runner(
            ["git", "remote", "get-url", "origin"], cwd=str(candidate), timeout=_COMMAND_TIMEOUT
        )
        _require_git(origin)
        try:
            same_origin = origin.succeeded and normalise_repo_url(origin.stdout.strip()) == repo_url
        except ValueError:
            same_origin = False
        if same_origin:
            root = candidate
            break
        if candidate == root:
            raise ValueError("cached repository origin does not match; choose another clone cache")

    if (root / ".git").exists():
        commit_sha = _head_sha(root, runner)
        if commit and not commit_sha.lower().startswith(commit.lower()):
            _fetch_commit(root, repo_url, commit, runner)
            commit_sha = _head_sha(root, runner)
            if not commit_sha.lower().startswith(commit.lower()):
                raise ValueError("requested commit does not match the cached repository revision")
        return RemoteSource(str(root), repo_url, commit_sha, reused=True)

    if commit:
        root.mkdir(parents=True, exist_ok=True)
        _fetch_commit(root, repo_url, commit, runner)
    else:
        _clone_default_branch(root, repo_url, runner)
    return RemoteSource(str(root), repo_url, _head_sha(root, runner))
