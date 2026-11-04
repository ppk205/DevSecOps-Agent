"""FR-61/68: one classification reaches scan and native bridge report exports."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from docx import Document

from tests.platform.test_scan_service import checkout, service, settings
from vulnscan.core.scan_service import ScanService

__all__ = ["checkout", "service"]
ROOT = Path(__file__).parents[2]
BINARY = ROOT / "bin" / ("devsecops-agent-go.exe" if os.name == "nt" else "devsecops-agent-go")


def check_exports(summary):
    payload = json.loads(Path(summary["reports"]["json"]).read_text(encoding="utf-8"))
    expected = payload["owasp_top10"]
    assert len(expected["categories"]) == 10
    assert any(c["cwes"] for c in expected["categories"] if c["id"] == "A05:2025")
    sarif = json.loads(Path(summary["reports"]["sarif"]).read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["owasp_top10"] == expected
    for fmt in ["html", "markdown", "txt"]:
        text = Path(summary["reports"][fmt]).read_text(encoding="utf-8")
        assert "OWASP Top 10:2025" in text and "CWE-89" in text
    word = Document(io.BytesIO(Path(summary["reports"]["docx"]).read_bytes()))
    assert any("OWASP Top 10:2025" in paragraph.text for paragraph in word.paragraphs)


def test_fr61_scan_service_exports_mapping_and_final_fallback(service, checkout, tmp_path):
    summary = service.run(
        str(checkout),
        settings(tmp_path, mode="deterministic", laya=False, tools=["semgrep", "gitleaks"]),
    )
    assert summary["status"] == "completed"
    check_exports(summary)
    narrative = Path(summary["reports"]["final-report"]).read_text(encoding="utf-8")
    assert "## OWASP Top 10:2025" in narrative and "CWE-89" in narrative


@pytest.mark.skipif(not BINARY.is_file(), reason="Build native binary for the real bridge test")
def test_fr68_native_completion_exports_same_owasp_section(checkout, tmp_path):
    db = tmp_path / "native.db"
    result = subprocess.run(
        [
            str(BINARY),
            "scan-run",
            "--checkout",
            str(checkout),
            "--db-path",
            str(db),
            "--out",
            str(tmp_path / "reports"),
            "--json",
        ],
        cwd=ROOT,
        env={
            **os.environ,
            "DEVSECOPS_PYTHON": sys.executable,
            "DEVSECOPS_RPC_MODULE": "tests.platform.rpc_fixture",
            "DEVSECOPS_FIXTURE_NATIVE_HUNT": "1",
            "DEVSECOPS_NATIVE": "python",
        },
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout[-2000:]
    summary = json.loads(result.stdout)
    check_exports(summary)
    assert ScanService(str(db)).summary(summary["id"])["status"] == "completed"
