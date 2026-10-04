"""The Java ruleset must cover common webapp vulnerability classes.

Every rule is exercised against a real Semgrep run, in both directions: it must
fire on the vulnerable fixture and stay silent on the safe one. A rule that
never fires is worse than no rule, because the scanner reports a clean repo.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "src" / "vulnscan" / "scanners" / "rules" / "java.yml"
SEMGREP = ROOT / ".venv" / "Scripts" / "semgrep.exe"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "java"

# rule id -> (vulnerable fixture, safe fixture)
CASES = {
    "java-xss-response-writer": ("VulnXss", "SafeXss"),
    "java-path-traversal-file": ("VulnPath", "SafePath"),
    "java-weak-cipher": ("VulnCipher", "SafeCipher"),
    "java-insecure-random": ("VulnRandom", "SafeRandom"),
    "java-unsafe-deserialization": ("VulnDeserialize", "SafeDeserialize"),
    "java-xxe-document-builder": ("VulnXxe", "SafeXxe"),
    "java-weak-cipher-secret-key": ("VulnKey", "SafeKey"),
    "java-trust-all-certificates": ("VulnTls", "SafeTls"),
    "java-unsafe-deserialization-objectmapper": ("VulnMapper", "SafeMapper"),
    "java-permissive-cors": ("VulnCors", "SafeCors"),
}


def _scan(tmp_path: Path, fixture: str) -> set[str]:
    """Run the project ruleset against one fixture in an isolated directory."""
    workdir = tmp_path / fixture
    workdir.mkdir(parents=True)
    shutil.copy(FIXTURES / f"{fixture}.java", workdir / f"{fixture}.java")
    result = subprocess.run(
        [
            str(SEMGREP),
            "scan",
            "--config",
            str(RULES),
            "--metrics=off",
            "--no-git-ignore",
            "--json",
            str(workdir),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    payload = json.loads(result.stdout[result.stdout.index("{") :])
    return {item["check_id"].split(".")[-1] for item in payload.get("results", [])}


@pytest.mark.parametrize("rule_id,fixtures", CASES.items())
def test_rule_fires_on_vulnerable_code(tmp_path: Path, rule_id: str, fixtures: tuple) -> None:
    assert _scan(tmp_path, fixtures[0]) == {rule_id}


@pytest.mark.parametrize("rule_id,fixtures", CASES.items())
def test_rule_stays_quiet_on_safe_code(tmp_path: Path, rule_id: str, fixtures: tuple) -> None:
    assert _scan(tmp_path, fixtures[1]) == set()


def test_console_logging_is_not_xss(tmp_path: Path) -> None:
    """Regression: System.out logging must not be reported as XSS."""
    assert _scan(tmp_path, "LogConsole") == set()


def test_static_json_response_is_not_xss(tmp_path: Path) -> None:
    """Regression: a constant JSON body is not an injection sink."""
    assert _scan(tmp_path, "StaticJson") == set()


def test_computed_response_still_flagged(tmp_path: Path) -> None:
    """Request data serialised then written is the real signal and must survive."""
    assert _scan(tmp_path, "ComputedXss") == {"java-xss-response-writer"}


def test_escaped_response_is_not_flagged(tmp_path: Path) -> None:
    """A declared sanitizer breaks the taint flow."""
    assert _scan(tmp_path, "SanitizedXss") == set()
