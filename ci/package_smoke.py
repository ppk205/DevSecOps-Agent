"""Build/install into a fresh environment, verify entrypoints and packaged assets."""

import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

from distributions import select_current

root = Path(__file__).resolve().parents[1]
if "--no-build" not in sys.argv:
    subprocess.run([sys.executable, "-m", "build", "--no-isolation"], cwd=root, check=True)
project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
wheel, source_path = select_current(root / "dist", project["name"], project["version"])
allowed = {
    "src",
    "tests",
    "docs",
    "ci",
    "cmd",
    "internal",
    "go.mod",
    "go.sum",
    "notebooks",
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "uv.lock",
    "requirements.lock",
    "requirements-build.lock",
    "requirements-scanners.lock",
    "action.yml",
    "PKG-INFO",
    ".gitignore",
}
with tarfile.open(source_path) as source:
    for member in source.getmembers():
        parts = Path(member.name).parts
        if len(parts) > 1 and parts[1] not in allowed:
            raise ValueError(f"Unintended source distribution entry: {member.name}")

with tempfile.TemporaryDirectory() as directory:
    env = Path(directory) / "env"
    subprocess.run([sys.executable, "-m", "venv", str(env)], check=True)
    binary = env / ("Scripts" if os.name == "nt" else "bin")
    python = binary / ("python.exe" if os.name == "nt" else "python")
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "-r",
            str(root / "requirements.lock"),
        ],
        check=True,
    )
    subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], check=True)
    subprocess.run(
        [str(python), "-I", str(root / "ci/smoke_installed.py")],
        cwd=directory,
        check=True,
    )
