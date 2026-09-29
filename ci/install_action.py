"""Install the Action's own revision in an isolated environment."""

import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = Path(os.environ["RUNNER_TEMP"]) / "devsecops-agent-venv"
subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
python = VENV / "bin/python"
subprocess.run(
    [
        str(python),
        "-m",
        "pip",
        "install",
        "--require-hashes",
        "-r",
        str(ROOT / "requirements-scanners.lock"),
    ],
    check=True,
)
subprocess.run(
    [str(python), "-m", "pip", "install", "--no-build-isolation", "--no-deps", str(ROOT)],
    check=True,
)
version = "8.24.2"
name = f"gitleaks_{version}_linux_x64.tar.gz"
base = f"https://github.com/gitleaks/gitleaks/releases/download/v{version}/"
with tempfile.TemporaryDirectory() as directory:
    archive = Path(directory) / name
    urllib.request.urlretrieve(base + name, archive)
    import hashlib

    expected = "fa0500f6b7e41d28791ebc680f5dd9899cd42b58629218a5f041efa899151a8e"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError("Gitleaks checksum mismatch")
    with tarfile.open(archive) as tar:
        member = tar.extractfile("gitleaks")
        assert member is not None
        binary = VENV / "bin/gitleaks"
        binary.write_bytes(member.read())
        binary.chmod(0o755)
with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as stream:
    stream.write(str(VENV / "bin") + "\n")
