"""Real scanner acceptance: safe passes, vulnerable fails the same policy."""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from vulnscan.core.config import ScanConfig
from vulnscan.core.scan_service import ScanService

root = Path(__file__).resolve().parents[1]
os.environ["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]
profile = "full" if "--full" in sys.argv else "fast"
with tempfile.TemporaryDirectory() as temporary:
    base = Path(temporary)
    for name, expected in [("safe", 0), ("vulnerable", 1)]:
        checkout = base / name
        shutil.copytree(root / "tests/fixtures/java" / name, checkout)
        (checkout / "pom.xml").write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>fixture</groupId><artifactId>fixture</artifactId><version>1.0</version><properties><maven.compiler.source>11</maven.compiler.source><maven.compiler.target>11</maven.compiler.target></properties></project>'
        )
        for args in [
            ["init"],
            ["add", "."],
            [
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        ]:
            subprocess.run(["git", *args], cwd=checkout, check=True, capture_output=True)
        result = ScanService(str(base / f"{name}.db")).run(
            str(checkout),
            ScanConfig(
                profile=profile,
                ci=True,
                timeout=3600,
                output_dir=os.environ.get(
                    "SCAN_INTEGRATION_OUTPUT", str(root / "artifacts/integration")
                ),
            ),
            on_event=lambda event, name=name: print(
                f"{profile} {name} {event.stage}: {event.status} {event.message}", flush=True
            ),
        )
        if result["exit_code"] != expected:
            raise AssertionError(
                f"{name}: expected {expected}; got {result['exit_code']}: {result['errors']}"
            )
        print(f"{profile} {name}: expected policy result {expected}")
