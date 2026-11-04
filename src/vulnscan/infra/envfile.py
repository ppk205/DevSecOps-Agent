"""Project-local ``.env`` management for API keys and provider settings.

Keys stay in the process environment (never embedded in reports or model
transcripts). This helper persists them to a gitignored ``.env`` file so a
first-time user can save a key once instead of exporting it every shell.

Security notes:

- The ``.env`` file is created with owner-only permissions (0600 on POSIX).
- Values are never logged; :func:`mask_secret` renders a safe placeholder.
- Existing process-environment values always win over the file, so CI
  secret injection keeps working.
"""

from __future__ import annotations

import os
from pathlib import Path

_ENV_FILENAME = ".env"
_FILE_LOADED_VALUES: dict[tuple[str, str], str] = {}


def mask_secret(value: str) -> str:
    """Return a display-safe placeholder that never contains the value."""
    if not value:
        return ""
    return "•••••••• (saved)"


def find_project_root(start: Path | str | None = None) -> Path:
    """Walk up from *start* to the directory holding ``pyproject.toml``.

    Falls back to the current working directory when no marker is found
    (e.g. a portable install without the repo layout).
    """
    current = Path(start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    return Path.cwd().resolve()


class EnvFile:
    """Minimal ``KEY=value`` reader/writer for the project ``.env`` file.

    Only the flat ``KEY=value`` shape is managed; comments and blank lines
    are preserved verbatim. Values with spaces or ``#`` are double-quoted.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        if path is None:
            path = find_project_root() / _ENV_FILENAME
        self.path = Path(path)

    def get(self, name: str) -> str | None:
        for key, value in self._read_pairs():
            if key == name:
                return value
        return None

    def names(self) -> list[str]:
        return [key for key, _ in self._read_pairs()]

    def is_configured(self, name: str) -> bool:
        value = os.environ.get(name, "").strip()
        if value:
            return True
        stored = self.get(name)
        return bool(stored and stored.strip())

    def set(self, name: str, value: str) -> Path:
        name = name.strip().upper().replace("-", "_")
        if not name.replace("_", "").isalnum() or not name:
            raise ValueError(f"Invalid environment variable name: {name!r}")
        value = value.strip()
        if not value:
            raise ValueError("Refusing to store an empty secret")
        lines = self._read_lines()
        rendered = f"{name}={_quote(value)}"
        for index, line in enumerate(lines):
            if _split_pair(line)[0] == name:
                lines[index] = rendered
                break
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(rendered + "\n")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("".join(lines), encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.path, 0o600)
        identity = (str(self.path.resolve()), name)
        previous = _FILE_LOADED_VALUES.get(identity)
        if previous is not None and os.environ.get(name) == previous:
            os.environ[name] = value
            _FILE_LOADED_VALUES[identity] = value
        return self.path

    def load_into_environ(self) -> list[str]:
        """Copy stored keys into ``os.environ`` without overriding it."""
        loaded: list[str] = []
        for key, value in self._read_pairs():
            if key and value and key not in os.environ:
                os.environ[key] = value
                _FILE_LOADED_VALUES[(str(self.path.resolve()), key)] = value
                loaded.append(key)
        return loaded

    # -- internals ------------------------------------------------------

    def _read_lines(self) -> list[str]:
        if not self.path.is_file():
            return []
        return self.path.read_text(encoding="utf-8").splitlines(keepends=True)

    def _read_pairs(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for line in self._read_lines():
            key, value = _split_pair(line)
            if key:
                pairs.append((key, value))
        return pairs


def _split_pair(line: str) -> tuple[str, str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return "", ""
    key, _, raw = stripped.partition("=")
    key = key.strip()
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    elif len(value) >= 2 and value[0] == value[-1] == "'":
        value = value[1:-1]
    comment_split = value.split(" #", 1)
    if not (raw.strip().startswith(('"', "'"))):
        value = comment_split[0].strip()
    if not key.replace("_", "").isalnum():
        return "", ""
    return key, value


def _quote(value: str) -> str:
    if any(ch in value for ch in (" ", "#", '"', "'")):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value
