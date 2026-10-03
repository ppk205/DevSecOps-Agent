"""Build/install into a fresh environment, verify entrypoints and packaged assets."""

import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
if "--no-build" not in sys.argv:
    subprocess.run([sys.executable, "-m", "build", "--no-isolation"], cwd=root, check=True)
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
with tarfile.open(next((root / "dist").glob("*.tar.gz"))) as source:
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
    wheel = next((root / "dist").glob("*.whl"))
    subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], check=True)
    subprocess.run([str(binary / "devsecops-agent"), "--version"], cwd=directory, check=True)
    subprocess.run([str(binary / "devsec"), "--version"], cwd=directory, check=True)
    subprocess.run(
        [
            str(python),
            "-c",
            "from importlib.resources import files; from vulnscan.tui.app import ScanApp; assert files('vulnscan.web').joinpath('templates/base.html').is_file(); assert files('vulnscan.scanners').joinpath('rules/java.yml').is_file()",
        ],
        cwd=directory,
        check=True,
    )
