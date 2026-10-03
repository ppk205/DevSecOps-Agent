"""Build versioned native release assets from the locked Go modules."""

from __future__ import annotations

import argparse
import os
import subprocess
import tomllib
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("bin"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    targets = (
        [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
        ]
        if args.all
        else [(None, None)]
    )
    args.out.mkdir(parents=True, exist_ok=True)
    for target_os, target_arch in targets:
        name = "devsecops-agent-go"
        if target_os:
            name += f"-{target_os}-{target_arch}"
        if (target_os or ("windows" if os.name == "nt" else "")) == "windows":
            name += ".exe"
        env = {**os.environ, "CGO_ENABLED": "0"}
        if target_os:
            env.update(GOOS=target_os, GOARCH=target_arch)
        subprocess.run(
            [
                args.go,
                "build",
                "-mod=readonly",
                "-trimpath",
                "-buildvcs=false",
                "-ldflags",
                f"-s -w -X main.version={version}",
                "-o",
                str(args.out / name),
                "./cmd/devsecops-agent",
            ],
            cwd=root,
            env=env,
            check=True,
        )


if __name__ == "__main__":
    main()
