"""Select this project's exact-version archives without touching older builds."""

import re
from pathlib import Path


def select_current(directory: Path, name: str, version: str) -> tuple[Path, Path]:
    normalized = re.sub(r"[-_.]+", "_", name)
    wheel = directory / f"{normalized}-{version}-py3-none-any.whl"
    source = directory / f"{normalized}-{version}.tar.gz"
    for path in (wheel, source):
        if not path.is_file():
            raise FileNotFoundError(f"Current distribution is missing: {path}")
    return wheel, source
