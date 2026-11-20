"""Install the Action's own revision in an isolated environment."""

import hashlib
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


def install_scanner(binary_name: str, url: str, checksum: str) -> None:
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / "scanner.tar.gz"
        urllib.request.urlretrieve(url, archive)
        with archive.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
                raise ValueError(f"{binary_name} checksum mismatch")
        with tarfile.open(archive) as tar:
            if not tar.getmember(binary_name).isfile():
                raise ValueError(f"invalid {binary_name} archive member")
            member = tar.extractfile(binary_name)
            assert member is not None
            binary = VENV / "bin" / binary_name
            binary.write_bytes(member.read())
        binary.chmod(0o755)


install_scanner(
    "gitleaks",
    "https://github.com/gitleaks/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_linux_x64.tar.gz",
    "fa0500f6b7e41d28791ebc680f5dd9899cd42b58629218a5f041efa899151a8e",
)
if os.environ.get("SCAN_PROFILE") == "full":
    install_scanner(
        "trivy",
        "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz",
        "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",
    )
with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as stream:
    stream.write(str(VENV / "bin") + "\n")
