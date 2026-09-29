"""Build from an explicit source-only context, excluding local targets and credentials."""

import shutil
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="vulnscan-image-") as temporary:
    context = Path(temporary)
    files = [
        root / n
        for n in [
            "requirements.lock",
            "requirements-build.lock",
            "pyproject.toml",
            "README.md",
            "ci/scanners.Dockerfile",
        ]
    ]
    files.extend(
        p for p in (root / "src").rglob("*") if p.is_file() and "__pycache__" not in p.parts
    )
    for source in files:
        target = context / source.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(context / "ci/scanners.Dockerfile"),
            "-t",
            "devsecops-agent-scanners:0.2.0",
            str(context),
        ],
        check=True,
    )
