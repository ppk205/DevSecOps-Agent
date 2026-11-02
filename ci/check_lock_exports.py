"""QR-22: compare every shipped requirements export to the frozen uv lock."""

from __future__ import annotations

import subprocess
from pathlib import Path

EXPORTS = {
    "requirements.lock": [],
    "requirements-build.lock": ["--group", "build"],
    "requirements-scanners.lock": ["--extra", "scanners", "--group", "build"],
}


def _requirements(text: str) -> list[str]:
    return [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]


def check(root: Path) -> int:
    failed = False
    for name, options in EXPORTS.items():
        result = subprocess.run(
            ["uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--no-header", *options],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        if _requirements(result.stdout) != _requirements((root / name).read_text(encoding="utf-8")):
            print(f"{name}: stale; regenerate this export from uv.lock")
            failed = True
        else:
            print(f"{name}: matches uv.lock")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(check(Path(__file__).resolve().parents[1]))
