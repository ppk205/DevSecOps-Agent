"""Verify installed assets, CVSS and non-interactive chat without model calls."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

_INSTALLED_CHECK = """\
from importlib.resources import files
from vulnscan.tui.app import ScanApp
from vulnscan.harness.console import ChatConsole
from vulnscan.harness.evidence import score_cvss4
from vulnscan.harness.gates import Gate, GateKeeper, GateRequest, refuse_all
assert files('vulnscan.web').joinpath('templates/base.html').is_file()
assert files('vulnscan.scanners').joinpath('rules/java.yml').is_file()
assert score_cvss4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N') == 9.3
keeper = GateKeeper(refuse_all, lambda event: None, mode='auto')
assert not keeper.ask(GateRequest(Gate.G0_SESSION, 'session', '')).approved
assert not keeper.ask(GateRequest(Gate.G6_FIX, 'fix', '')).approved
"""


def main() -> None:
    env = {
        **os.environ,
        "DEVSECOPS_NATIVE": "python",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
    }
    with tempfile.TemporaryDirectory(prefix="devsec-installed-") as directory:
        cwd = Path(directory)
        subprocess.run(
            [sys.executable, "-I", "-c", _INSTALLED_CHECK],
            cwd=cwd,
            env=env,
            check=True,
            timeout=60,
        )
        suffix = ".exe" if os.name == "nt" else ""
        for alias in ("devsecops-agent", "devsec"):
            command = str(Path(sys.executable).parent / (alias + suffix))
            subprocess.run([command, "--version"], cwd=cwd, env=env, check=True, timeout=30)
            subprocess.run(
                [command, "chat", "--help"],
                cwd=cwd,
                env=env,
                check=True,
                stdout=subprocess.DEVNULL,
                timeout=30,
            )
            result = subprocess.run(
                [
                    command,
                    "chat",
                    "--target",
                    str(cwd),
                    "--provider",
                    "ollama",
                    "--model",
                    "fixture",
                    "--sessions-dir",
                    str(cwd / "sessions"),
                    "-p",
                    "Do not call a provider",
                ],
                cwd=cwd,
                env=env,
                input="",
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 2 or "G0 needs a human" not in result.stdout:
                raise RuntimeError(
                    f"{alias}: non-interactive chat did not refuse G0: {result.stdout} {result.stderr}"
                )
        print("Installed chat refused G0 for both aliases; assets, CVSS and G6 refusal passed.")


if __name__ == "__main__":
    main()
