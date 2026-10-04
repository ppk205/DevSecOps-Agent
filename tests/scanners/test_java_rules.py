"""The Java ruleset must cover common webapp vulnerability classes.

Every rule is exercised against a real Semgrep run, in both directions: it must
fire on the vulnerable fixture and stay silent on the safe one. A rule that
never fires is worse than no rule, because the scanner reports a clean repo.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sysconfig
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "src" / "vulnscan" / "scanners" / "rules" / "java.yml"
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


@pytest.fixture(scope="session")
def semgrep() -> str:
    """QR-20/23: find the provisioned scanner on any supported platform."""
    executable = shutil.which("semgrep")
    if executable:
        return executable
    script = Path(sysconfig.get_path("scripts")) / ("semgrep.exe" if os.name == "nt" else "semgrep")
    if not script.is_file():
        pytest.fail("Semgrep is required: install the project with the scanners extra")
    return str(script)


def _scan(tmp_path: Path, fixture: str, semgrep: str) -> set[str]:
    """Run the project ruleset against one fixture in an isolated directory."""
    workdir = tmp_path / fixture
    workdir.mkdir(parents=True)
    shutil.copy(FIXTURES / f"{fixture}.java", workdir / f"{fixture}.java")
    result = subprocess.run(
        [
            semgrep,
            "scan",
            "--config",
            str(RULES),
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--json",
            str(workdir),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    payload = json.loads(result.stdout[result.stdout.index("{") :])
    assert not payload.get("errors"), payload["errors"]
    return {item["check_id"].split(".")[-1] for item in payload.get("results", [])}


@pytest.mark.parametrize("rule_id,fixtures", CASES.items())
def test_rule_fires_on_vulnerable_code(
    tmp_path: Path, rule_id: str, fixtures: tuple, semgrep: str
) -> None:
    assert _scan(tmp_path, fixtures[0], semgrep) == {rule_id}


@pytest.mark.parametrize("rule_id,fixtures", CASES.items())
def test_rule_stays_quiet_on_safe_code(
    tmp_path: Path, rule_id: str, fixtures: tuple, semgrep: str
) -> None:
    assert _scan(tmp_path, fixtures[1], semgrep) == set()


def test_console_logging_is_not_xss(tmp_path: Path, semgrep: str) -> None:
    """Regression: System.out logging must not be reported as XSS."""
    assert _scan(tmp_path, "LogConsole", semgrep) == set()


def test_static_json_response_is_not_xss(tmp_path: Path, semgrep: str) -> None:
    """Regression: a constant JSON body is not an injection sink."""
    assert _scan(tmp_path, "StaticJson", semgrep) == set()


def test_computed_response_still_flagged(tmp_path: Path, semgrep: str) -> None:
    """Request data serialised then written is the real signal and must survive."""
    assert _scan(tmp_path, "ComputedXss", semgrep) == {"java-xss-response-writer"}


def test_escaped_response_is_not_flagged(tmp_path: Path, semgrep: str) -> None:
    """A declared sanitizer breaks the taint flow."""
    assert _scan(tmp_path, "SanitizedXss", semgrep) == set()


@pytest.mark.parametrize(
    "fixture",
    [
        "VulnTrustManager",
        "VulnNamedTrustManager",
        "VulnHostnameVerifier",
        "VulnNamedHostnameVerifier",
        "VulnInstanceHostnameVerifier",
    ],
)
def test_fr23_tls_verification_bypasses_are_detected(
    tmp_path: Path, semgrep: str, fixture: str
) -> None:
    assert _scan(tmp_path, fixture, semgrep) == {"java-trust-all-certificates"}


@pytest.mark.parametrize("fixture", ["SafeTrustManager", "SafeHostnameVerifier", "UnrelatedInit"])
def test_fr23_validating_tls_and_unrelated_methods_are_not_flagged(
    tmp_path: Path, semgrep: str, fixture: str
) -> None:
    assert _scan(tmp_path, fixture, semgrep) == set()
