"""Install missing local dependencies, then launch the app.

Standard library only, so any Python 3.11+ can run it before ``.venv`` exists.

    python ci/launch.py              web UI at http://127.0.0.1:8000/app/
    python ci/launch.py web ARGS     ``serve`` with ARGS instead of the defaults
    python ci/launch.py go ARGS      Go CLI (for example ``go tui`` or ``go scan-list``)
    python ci/launch.py cli ARGS     Python CLI

Each step only runs when something is missing or older than its sources:
``uv sync --frozen --inexact --extra scanners`` for Python packages, ``npm ci`` and
``npm run build`` for the web UI, ``ci/build_native.py`` for the Go binary, and a
pinned, checksum-verified Gitleaks release placed in the virtualenv's script folder.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web-ui"
EXE = ".exe" if sys.platform == "win32" else ""
GO_BINARY = ROOT / "bin" / f"devsecops-agent-go{EXE}"

# Same version as ci/install_action.py; hashes from the release's checksums.txt.
GITLEAKS_VERSION = "8.24.2"
GITLEAKS_SHA256 = {
    "gitleaks_8.24.2_windows_x64.zip": "cc47fdc0364964e2d346fbbcbe4cc87f34d490b2647508fb05930d0ec2fbff07",
    "gitleaks_8.24.2_linux_x64.tar.gz": "fa0500f6b7e41d28791ebc680f5dd9899cd42b58629218a5f041efa899151a8e",
    "gitleaks_8.24.2_linux_arm64.tar.gz": "574a6d52573c61173add7ddb5e3cc68c0e82cb0735818a1eeb9a0a2de1643fbc",
    "gitleaks_8.24.2_darwin_x64.tar.gz": "bc3c46f8039ba716ba8461fa6745c9d1cfb90ca2f5f881d8d0cf66b7ba7b742c",
    "gitleaks_8.24.2_darwin_arm64.tar.gz": "90d13686937ac7429b97a3acbf1e1d0ce90d92ae2d0cf46a690bd8ae5230bea0",
}


def step(message: str) -> None:
    print(f"[launch] {message}", flush=True)


def run(command: list[str | Path], **kwargs) -> None:
    subprocess.run([str(part) for part in command], check=True, **kwargs)


def newest(*sources: Path) -> float:
    times = [0.0]
    for source in sources:
        if source.is_file():
            times.append(source.stat().st_mtime)
        elif source.is_dir():
            times.extend(p.stat().st_mtime for p in source.rglob("*") if p.is_file())
    return max(times)


def stale(target: Path, *sources: Path) -> bool:
    return not target.exists() or newest(*sources) > target.stat().st_mtime


def venv_python() -> Path:
    venv = Path(os.environ.get("UV_PROJECT_ENVIRONMENT") or ROOT / ".venv")
    if not venv.is_absolute():
        venv = ROOT / venv
    return venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def ensure_python() -> Path:
    python = venv_python()
    uv = shutil.which("uv")
    if uv:
        # --inexact keeps extras already installed in the environment, such as dev tools.
        step("syncing Python packages from uv.lock")
        run([uv, "sync", "--frozen", "--inexact", "--extra", "scanners"], cwd=ROOT)
    elif not python.exists():
        sys.exit("[launch] uv is required to create the environment: https://docs.astral.sh/uv/")
    else:
        step("uv not found; using the existing environment without syncing")
    return python


def ensure_web() -> None:
    npm = shutil.which("npm")
    lock = WEB / "package-lock.json"
    if stale(WEB / "node_modules" / ".package-lock.json", lock):
        if not npm:
            sys.exit("[launch] Node.js 18+ (npm) is required for the web UI")
        step("installing web UI packages (npm ci)")
        run([npm, "ci"], cwd=WEB)
    sources = [WEB / name for name in ("src", "index.html", "vite.config.ts", "package.json")]
    if stale(WEB / "dist" / "index.html", lock, *sources):
        if not npm:
            sys.exit("[launch] Node.js 18+ (npm) is required for the web UI")
        step("building the web UI (npm run build)")
        run([npm, "run", "build"], cwd=WEB)


def ensure_go() -> None:
    sources = [ROOT / name for name in ("cmd", "internal", "go.mod", "go.sum")]
    if not stale(GO_BINARY, *sources):
        return
    local = ROOT / ".tools" / "go" / "bin" / f"go{EXE}"
    go = shutil.which("go") or (str(local) if local.exists() else None)
    if not go:
        # ponytail: no Go SDK download; prebuilt bin/ output or a manual install covers it.
        if GO_BINARY.exists():
            step("Go SDK not found; using the existing, older Go binary")
            return
        sys.exit("[launch] Go SDK not found; install Go 1.26+ or put it in .tools/go")
    step("building the Go binary")
    run([sys.executable, ROOT / "ci" / "build_native.py", "--go", go], cwd=ROOT)


def gitleaks_asset(system: str, machine: str) -> str | None:
    os_name = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(system)
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(
        machine.lower()
    )
    extension = "zip" if os_name == "windows" else "tar.gz"
    name = f"gitleaks_{GITLEAKS_VERSION}_{os_name}_{arch}.{extension}"
    return name if name in GITLEAKS_SHA256 else None


def install_gitleaks(directory: Path, asset: str) -> Path:
    base = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/"
    member = "gitleaks.exe" if asset.endswith(".zip") else "gitleaks"
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / asset
        urllib.request.urlretrieve(base + asset, archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != GITLEAKS_SHA256[asset]:
            raise ValueError(f"Gitleaks checksum mismatch for {asset}")
        if asset.endswith(".zip"):
            with zipfile.ZipFile(archive) as bundle:
                data = bundle.read(member)
        else:
            with tarfile.open(archive) as bundle:
                stream = bundle.extractfile(member)
                if stream is None:
                    raise ValueError(f"{member} missing from {asset}")
                data = stream.read()
    binary = directory / member
    binary.write_bytes(data)
    binary.chmod(0o755)
    return binary


def ensure_gitleaks(python: Path) -> None:
    # Scanners also look in the interpreter's script folder (scanners/platform.py).
    scripts = python.parent
    if shutil.which("gitleaks") or (scripts / f"gitleaks{EXE}").exists():
        return
    asset = gitleaks_asset(sys.platform, platform.machine())
    if not asset:
        step("no pinned Gitleaks build for this platform; secret scanning stays unavailable")
        return
    step(f"installing Gitleaks {GITLEAKS_VERSION} into {scripts}")
    try:
        install_gitleaks(scripts, asset)
    except (OSError, ValueError) as error:
        step(f"Gitleaks not installed ({error}); scans will report it as unavailable")


def main(argv: list[str]) -> int:
    mode, args = (argv[0], argv[1:]) if argv else ("web", [])
    if mode not in {"web", "go", "cli"}:
        sys.exit(f"[launch] unknown mode {mode!r}; use web, go or cli")
    python = ensure_python()
    ensure_gitleaks(python)
    env = dict(os.environ)
    if mode == "web":
        ensure_web()
        env["DEVSECOPS_NATIVE"] = "python"
        command = [python, "-m", "vulnscan.cli.main", "serve"]
        command += args or ["--host", "127.0.0.1", "--port", "8000"]
        step("web UI: http://127.0.0.1:8000/app/ (Ctrl+C to stop)")
    elif mode == "go":
        ensure_go()
        env["DEVSECOPS_PYTHON"] = str(python)
        command = [GO_BINARY, *args]
    else:
        command = [python, "-m", "vulnscan.cli.main", *args]
    try:
        return subprocess.run([str(part) for part in command], env=env, check=False).returncode
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
